#include <array>
#include <asio.hpp>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

struct Reply {
  int code;
  std::string text;
};

// Keep this buffer across reads: TCP can deliver several replies together.
Reply readReply(asio::ip::tcp::socket &socket, asio::streambuf &buffer) {
  auto readLine = [&]() {
    asio::read_until(socket, buffer, "\r\n");
    std::istream input(&buffer);
    std::string line;
    std::getline(input, line);
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    std::cout << line << '\n';
    return line;
  };
  std::string first = readLine();
  if (first.size() < 4 || !std::isdigit(static_cast<unsigned char>(first[0])) ||
      !std::isdigit(static_cast<unsigned char>(first[1])) ||
      !std::isdigit(static_cast<unsigned char>(first[2])) ||
      (first[3] != ' ' && first[3] != '-'))
    throw std::runtime_error("Invalid FTP reply");
  int code = std::stoi(first.substr(0, 3));
  std::string text = first;
  if (first[3] == '-') {
    const std::string ending = first.substr(0, 3) + " ";
    for (;;) {
      auto line = readLine();
      text += '\n' + line;
      if (line.compare(0, ending.size(), ending) == 0)
        break;
    }
  }
  return {code, text};
}

void sendCommand(asio::ip::tcp::socket &socket, const std::string &command) {
  std::string line = command + "\r\n";
  asio::write(socket, asio::buffer(line)); // Send the entire command.
}

std::pair<std::string, std::string> splitCommand(const std::string &line) {
  auto space = line.find(' ');
  auto name = line.substr(0, space);
  for (auto &c : name)
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return {name, space == std::string::npos ? "" : line.substr(space + 1)};
}

asio::ip::tcp::endpoint passiveEndpoint(const Reply &reply) {
  auto begin = reply.text.find('(');
  auto end = reply.text.find(')', begin);
  if (begin == std::string::npos || end == std::string::npos)
    throw std::runtime_error("Invalid PASV reply");
  std::string numbers = reply.text.substr(begin + 1, end - begin - 1);
  for (auto &c : numbers)
    if (c == ',')
      c = ' ';
  std::istringstream input(numbers);
  std::array<int, 6> fields{};
  for (auto &field : fields) {
    if (!(input >> field) || field < 0 || field > 255)
      throw std::runtime_error("Invalid PASV endpoint");
  }
  std::string address =
      std::to_string(fields[0]) + "." + std::to_string(fields[1]) + "." +
      std::to_string(fields[2]) + "." + std::to_string(fields[3]);
  return {asio::ip::make_address(address),
          static_cast<unsigned short>(fields[4] * 256 + fields[5])};
}

int main() {
  try {
    asio::io_context context;
    asio::ip::tcp::socket socket(context);
    socket.connect({asio::ip::make_address("127.0.0.1"), 2121});
    asio::streambuf replies;
    if (readReply(socket, replies).code != 220)
      return 1;

    for (;;) {
      std::string username, password;
      std::cout << "Username: ";
      if (!std::getline(std::cin, username))
        return 0;
      sendCommand(socket, "USER " + username);
      auto reply = readReply(socket, replies);
      if (reply.code == 230)
        break;
      if (reply.code != 331)
        continue;
      std::cout << "Password: ";
      if (!std::getline(std::cin, password))
        return 0;
      sendCommand(socket, "PASS " + password);
      password.clear();
      if (readReply(socket, replies).code == 230)
        break;
    }

    std::unique_ptr<asio::ip::tcp::socket> dataSocket;
    for (;;) {
      std::cout
          << "FTP command (PASV, LIST, RETR, STOR, PWD, CWD, RNFR, QUIT): ";
      std::string line;
      if (!std::getline(std::cin, line)) {
        sendCommand(socket, "QUIT");
        readReply(socket, replies);
        break;
      }
      auto [command, argument] = splitCommand(line);
      if (command.empty())
        continue;
      if (command == "MKDIR")
        command = "MKD";
      line = command + (argument.empty() ? "" : " " + argument);
      bool transfer =
          command == "LIST" || command == "RETR" || command == "STOR";
      std::ifstream source;
      std::ofstream destination;
      if (transfer) {
        if ((command == "RETR" || command == "STOR") && argument.empty()) {
          std::cerr << "A filename is required\n";
          continue;
        }
        if (command == "STOR") {
          source.open(argument, std::ios::binary);
          if (!source) {
            std::cerr << "Cannot open local source file\n";
            continue;
          }
        }
        // Preserve the existing workflow: PASV may be issued explicitly.
        // Otherwise negotiate it automatically before a transfer.
        if (!dataSocket) {
          sendCommand(socket, "PASV");
          auto passive = readReply(socket, replies);
          if (passive.code != 227)
            continue;
          dataSocket = std::make_unique<asio::ip::tcp::socket>(context);
          dataSocket->connect(passiveEndpoint(passive));
        }
      }
      sendCommand(socket, line);
      auto reply = readReply(socket, replies);
      if (command == "PASV") {
        dataSocket.reset();
        if (reply.code == 227) {
          dataSocket = std::make_unique<asio::ip::tcp::socket>(context);
          dataSocket->connect(passiveEndpoint(reply));
        }
      } else if (transfer) {
        if (reply.code != 150 && reply.code != 125) {
          dataSocket.reset();
          continue;
        }
        std::array<char, 20 * 1024> data{};
        if (command == "STOR") {
          while (source.read(data.data(), data.size()) || source.gcount() > 0)
            asio::write(*dataSocket,
                        asio::buffer(data.data(), source.gcount()));
          if (source.bad())
            throw std::runtime_error("Local file read failed");
          dataSocket->shutdown(asio::ip::tcp::socket::shutdown_send);
        } else {
          if (command == "RETR") {
            destination.open(std::filesystem::path(argument).filename(),
                             std::ios::binary);
            if (!destination)
              throw std::runtime_error("Cannot open local destination file");
          }
          for (;;) {
            asio::error_code error;
            auto size = dataSocket->read_some(asio::buffer(data), error);
            if (size) {
              if (command == "LIST")
                std::cout.write(data.data(), size);
              else {
                destination.write(data.data(), size);
                if (!destination)
                  throw std::runtime_error("Local file write failed");
              }
            }
            if (error == asio::error::eof)
              break;
            if (error)
              throw asio::system_error(error);
          }
          if (command == "RETR") {
            destination.close();
            if (destination.fail())
              throw std::runtime_error("Local file close failed");
          }
        }
        dataSocket.reset();
        readReply(socket, replies); // Consume the transfer's final reply.
      } else if (command == "QUIT") {
        break; // 221 has been received before disconnecting.
      } else if (command == "RNFR" && reply.code == 350) {
        std::cout << "Destination (RNTO new-name): ";
        if (!std::getline(std::cin, line))
          break;
        auto destinationCommand = splitCommand(line);
        if (destinationCommand.first != "RNTO")
          line = "RNTO " + line;
        sendCommand(socket, line);
        readReply(socket, replies);
      }
    }
  } catch (const std::exception &error) {
    std::cerr << "FTP client error: " << error.what() << '\n';
    return 1;
  }
}

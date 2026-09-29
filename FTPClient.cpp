#include <asio.hpp>
#include <bits/stdc++.h>
#include <cstddef>
std::vector<uint8_t> vByts(20 * 1024);

int main() {
  asio::io_context context;
  asio::ip::tcp::socket socket(context);
  asio::error_code ec;
  socket.connect(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 2121), ec);
  if (!ec) {
    std::cout << "Connected ";
    std::string current_path;
    while (true) {
      std::cout << "What do you want to do?CWD, PWD \n";
      std::string command;
      std::getline(std::cin, command);
      std::string request = "PASV\r\n";

      if (command.find("CWD") != std::string::npos ||
          command.find("CDUP") != std::string::npos) {
        command.append("\r\n");

        request = command;
        socket.write_some(asio::buffer(request.data(), request.size()));
        socket.wait(socket.wait_write);

      } else if (command.find("QUIT") != std::string::npos) {
        command.append("\r\n");
        request = command;
        socket.write_some(asio::buffer(request.data(), request.size()));
        socket.shutdown(asio::ip::tcp::socket::shutdown_send);
        break;
      } else if (command.find("PWD") != std::string::npos) {
        command.append("\r\n");
        request = command;

        socket.write_some(asio::buffer(request.data(), request.size()));

        std::size_t n =

            socket.read_some(asio::buffer(vByts.data(), vByts.size()), ec);
        // socket.wait(socket.wait_read);
        std::cout << std::string(reinterpret_cast<const char *>(vByts.data()),
                                 n)
                  << " is the PWD\n";
      } else {

        socket.write_some(asio::buffer(request.data(), request.size()));
        socket.wait(socket.wait_write);
        std::size_t n =
            socket.read_some(asio::buffer(vByts.data(), vByts.size()), ec);

        std::string s(reinterpret_cast<const char *>(vByts.data()), n);
        std::cout << s << std::endl;
        asio::ip::tcp::socket socket2(context);
        char *tok = std::strtok(s.data(), "(");
        tok = std::strtok(nullptr, ")");
        char *info = std::strtok(tok, ",");
        int count = 0;
        std::string newIp;
        int port, portA, portB;
        while (info != nullptr) {
          std::cout << info << " is tok\n";
          if (count < 4) {
            std::string aux(info);
            newIp.append(aux);
            if (count < 3) {
              newIp.push_back('.');
            }
          } else {
            if (count == 4)
              portA = std::stoi(info);

            else {
              port = portA * 256 + std::stoi(info);
            }
          }
          count++;
          info = std::strtok(nullptr, ",");
        }
        std::cout << "IP is: " << newIp << " and port is:" << port << std::endl;
        socket2.connect(
            asio::ip::tcp::endpoint(asio::ip::make_address(newIp), port), ec);
        std::string response = "LIST\r\n";
        socket.write_some(asio::buffer(response.data(), response.size()), ec);
        if (!ec || ec == asio::error::eof) {
          n = socket2.read_some(asio::buffer(vByts.data(), vByts.size()), ec);
          if (!ec || ec == asio::error::eof) {
            std::cout.write(reinterpret_cast<const char *>(vByts.data()), n);
          }
        }
      }
    }

  } else {
    std::cout << ec;
  }
}

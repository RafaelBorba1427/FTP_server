#include <asio.hpp>
#include <bits/stdc++.h>
std::vector<char> commandBuffer(600);
std::vector<uint8_t> dataBuffer(20 * 1024);
asio::io_context context;
// max size of buffer is 20*1024
enum class PASV_commands { NONE, LIST };

PASV_commands pasvCommands = PASV_commands::NONE;
// TODO::make the reading of the list actually make it send the list,add the
// rest of the functions
std::stack<std::string> navigation;
std::string LIST(std::string path) {
  std::string out;
  std::cout << "path in list function is: " << path << std::endl;
  for (auto entry : std::filesystem::directory_iterator(path)) {
    out.append(entry.path().string());
    out.append("\n");
  }
  return out;
}
std::string CDUP(std::string path) {
  std::string s = navigation.top();
  navigation.pop();
  return s;
}

std::string CWD(std::string path, std::string next) {

  if (!next.compare("..")) {
    return CDUP(path);
  }
  std::string list = LIST(path);
  if (list.empty())
    return path;
  if (list.find(next) != std::string::npos) {
    navigation.push(path);
    path.append("/");
    return path.append(next);
  }
  return path;
}

void handleconnection(std::shared_ptr<asio::ip::tcp::socket> sock,
                      std::shared_ptr<asio::streambuf> buffer,
                      std::shared_ptr<std::string> path) {

  asio::async_read_until(
      *sock, *buffer, "\n",
      [sock, buffer, path](std::error_code ec, std::size_t) {
        if (!ec || ec == asio::error::eof) {
          std::cout << "received\n";
          std::istream is(buffer.get());
          std::string line;
          std::getline(is, line);
          auto oct = sock->local_endpoint().address().to_v4().to_bytes();
          auto sock2 = std::make_shared<asio::ip::tcp::socket>(context);

          if (line.find("LIST") != std::string::npos) {
            std::cout << "LIST received\n";
            pasvCommands = PASV_commands::LIST;
          } else if (line.find("PASV") != std::string::npos) {
            std::cout << "PASV received\n";
            auto response = std::make_shared<std::string>(
                "227 dataconnection open (" + std::to_string(oct[0]) + "," +
                std::to_string(oct[1]) + "," + std::to_string(oct[2]) + "," +
                std::to_string(oct[3]) + ",7,228)\r\n");

            std::error_code ec;
            // send data based on line
            auto accept = std::make_shared<asio::ip::tcp::acceptor>(
                context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 2020));

            accept->async_accept(*sock2, [sock2, sock, accept,
                                          path](asio::error_code ec) {
              if (!ec) {
                std::cout << "new socket connected\n";
                std::string response = LIST(*path);
                std::cout << "path is: " << *path << std::endl;
                asio::async_write(
                    *sock2, asio::buffer(response.data(), response.size()),
                    [sock2, response](asio::error_code ec, std::size_t) {
                      if (!ec) {
                        std::cout << "sent LIST\n";
                        sock2->shutdown(asio::ip::tcp::socket::shutdown_both,
                                        ec);
                        sock2->close();
                      }
                    });
              }
            });

            asio::async_write(*sock,
                              asio::buffer(response->data(), response->size()),
                              [sock, response, path, line](std::error_code ec,
                                                           std::size_t length) {
                                if (!ec) {
                                  std::cout << "new IP sent\n";

                                } else {
                                  std::cout << "error in sending message: "
                                            << ec.message() << "\n";
                                }
                              });
          } else if (line.find("CWD") != std::string::npos) {
            std::cout << line << std::endl;
            size_t sp = line.find(' ');
            if (sp != std::string::npos) {
              std::string s =
                  line.substr(sp + 1); // everything after the first space
              while (s.at(s.size() - 1) == '\r' || s.at(s.size() - 1) == '\n') {
                s.pop_back();
              }
              *path = CWD(*path, s);
            }
          } else if (line.find("CDUP") != std::string::npos) {
            *path = CDUP(*path);
          } else if (line.find("PWD") != std::string::npos) {
            std::cout << "PWD received";

            std::string s(*path);
            std::cout << "s is: " << s << std::endl;

            auto response = std::make_shared<std::string>("257 " + s);
            asio::async_write(
                *sock, asio::buffer(response->data(), response->size()),
                [sock, response](asio::error_code ec, std::size_t) {
                  if (!ec) {
                    std::cout << "PWD written";
                  } else {
                    std::cout << "ERROR PWD\n";
                  }
                });

          } else if (line.find("QUIT") != std::string::npos) {
            // CWD(path);
            sock->close();
            return;
            std::cout << line << std::endl;
          }
          handleconnection(sock, buffer, path);
        } else {
          std::cout << "error in receive: " << ec.message() << "\n";
        }

        std::cout << "client connected\n";
      });
}
void acceptance(asio::ip::tcp::acceptor &acceptor) {
  asio::ip::tcp::resolver resolver(context);
  auto socket = std::make_shared<asio::ip::tcp::socket>(context);

  acceptor.async_accept(*socket, [socket, &acceptor](std::error_code ec) {
    if (!ec) {
      auto buffer = std::make_shared<asio::streambuf>();
      std::cout << "client connected\n";
      handleconnection(
          socket, buffer,
          std::make_shared<std::string>("/home/rafa/Desktop/MyStuff"));
      acceptance(acceptor);

    } else {
      socket->close();
    }
  });
}

int main() {
  auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(
      context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 2121));

  acceptance(*acceptor);
  try {
    context.run();
  } catch (std::exception e) {
    std::cout << e.what() << " is a context error";
  }
  // acceptor->close();
}

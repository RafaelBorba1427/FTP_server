#include <asio.hpp>
#include <bits/stdc++.h>
#include <iostream>
#include <pwd.h>
#include <security/_pam_types.h>
#include <security/pam_appl.h>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <unordered_map>
// Username -> encoded password hash, including salt and settings.
std::unordered_map<std::string, std::string> users;

std::vector<char> commandBuffer(600);
asio::io_context context;
// max size of buffer is 20*1024

enum state { NONE, RENAME, FILERECEIVE, FILERECNAME, NEWSOCK, USER, PASS };

class Session {
public:
  struct PendingReply {
    std::shared_ptr<std::string> text;
    std::function<void()> afterSend;
  };
  std::deque<PendingReply> replies;
  asio::streambuf controlBuffer;
  std::shared_ptr<asio::ip::tcp::acceptor> passiveAcceptor;
  std::shared_ptr<std::string> pendingDataCommand;
  bool transferActive = false;
  bool closing = false;
  struct PasswordData {
    struct response {
      std::string prompt, value;
      response(std::string prompt, std::string value)
          : prompt(prompt), value(value) {}
    };
    std::vector<response> responseData;
    int addPrompt(std::string prompt, std::string value) {
      if (value.size() + 1 > PAM_MAX_MSG_SIZE) {
        std::clog << "PAM value length error: " << prompt << "\n";
        return PAM_CONV_ERR;
      }
      responseData.emplace_back(prompt, value);
      return PAM_SUCCESS;
    }
    void clearPrompt() {
      while (responseData.size() > 0) {
        responseData.pop_back();
      }
    }
    int makeResponse(const pam_message &msg, pam_response &response) {
      response.resp_retcode = 0;
      switch (msg.msg_style) {
      case PAM_PROMPT_ECHO_ON: {

        std::string prompt(msg.msg);
        for (struct response it : responseData) {
          if (it.prompt == prompt) {
            std::clog << "PAM visible prompt: " << prompt << "\n";
            response.resp = strdup(it.value.c_str());
            return response.resp ? PAM_SUCCESS : PAM_BUF_ERR;
          }
        }
        return PAM_CONV_ERR;
      }
      case PAM_PROMPT_ECHO_OFF: {
        std::string prompt(msg.msg);
        for (struct response it : responseData) {
          if (it.prompt == prompt) {
            response.resp = strdup(it.value.c_str());
            return response.resp ? PAM_SUCCESS : PAM_BUF_ERR;
          }
        }
        return PAM_CONV_ERR;
      }
      case PAM_ERROR_MSG:
        std::clog << "PAM error: " << msg.msg << "\n";
        break;

      case PAM_TEXT_INFO:
        std::clog << "PAM info: " << msg.msg << "\n";
        break;
      default:
        return PAM_CONV_ERR;
      }
      return PAM_SUCCESS;
    }
  };

  bool getAuth() { return authenticated; }
  void setAuth(bool authenticated) { this->authenticated = authenticated; }
  void setUser(std::string user) { this->user = user; }
  PasswordData &getPassword() { return passwordStuff; }
  std::string getUser() { return user; }

  void setPath(std::string value) {
    this->path = std::make_shared<std::string>(value);
  }

  std::shared_ptr<std::string> getPath() { return path; }
  void setPastFile(std::string past_filename) {
    this->past_filename = past_filename;
  }
  std::string getPastFile() { return past_filename; }
  std::shared_ptr<asio::ip::tcp::socket> getSock() { return sock; }
  std::shared_ptr<asio::ip::tcp::socket> getDataSock() { return dataSock; }
  void setDataSock(std::shared_ptr<asio::ip::tcp::socket> dataSock) {
    this->dataSock = dataSock;
  }
  state getCurrent() { return current; }
  void setCurrent(state current) { this->current = current; }
  Session(std::shared_ptr<asio::ip::tcp::socket> sock,
          std::shared_ptr<std::string> path) {
    this->sock = sock;
    this->path = path;
    this->current = NONE;
    authenticated = false;
  }
  void setPass(std::string pass) { this->pass = pass; }
  std::string getPass() { return pass; }

private:
  std::shared_ptr<asio::ip::tcp::socket> sock;
  std::shared_ptr<asio::ip::tcp::socket> dataSock;
  std::shared_ptr<std::string> path;
  std::string past_filename;
  std::string pass;
  state current;
  std::string user;
  bool authenticated;
  PasswordData passwordStuff;
};

int pamFunctionConversation(int numMsg, const struct pam_message **msgs,
                            struct pam_response **resp, void *appdataPtr) {
  if (appdataPtr == nullptr || msgs == nullptr || resp == nullptr ||
      numMsg <= 0 || numMsg >= PAM_MAX_NUM_MSG) {
    return PAM_CONV_ERR;
  }
  Session::PasswordData *appPass =
      reinterpret_cast<Session::PasswordData *>(appdataPtr);
  size_t msgCount = (size_t)(numMsg);
  auto *responseArrPtr =
      static_cast<pam_response *>(std::calloc(msgCount, sizeof(pam_response)));
  if (!responseArrPtr) {
    return PAM_BUF_ERR;
  }
  auto *responses = responseArrPtr;
  for (size_t i = 0; i < msgCount; i++) {
    const pam_message &mess = *(msgs[i]);
    pam_response &responde = responses[i];
    responde.resp_retcode = 0;
    responde.resp = nullptr;
    int r = appPass->makeResponse(mess, responde);
    if (r != PAM_SUCCESS) {
      for (size_t j = 0; j <= i; j++) {
        std::free(responseArrPtr[j].resp);
      }
      std::free(responseArrPtr);
      return r;
    }
  }
  *resp = responseArrPtr;
  return PAM_SUCCESS;
}

int pamAutenticateUser(std::shared_ptr<Session> client,
                       std::optional<std::string> token) {
  Session::PasswordData *data = &client->getPassword();
  if (int ret = data->addPrompt("Password: ", client->getPass());
      ret != PAM_SUCCESS) {
    return ret;
  }
  if (token) {
    if (int ret = data->addPrompt("Verification code: ", *token);
        ret != PAM_SUCCESS) {
      return ret;
    }
  }

  const struct pam_conv localConversation = {pamFunctionConversation, data};
  pam_handle_t *localAuthHandle = nullptr;

  int retval = pam_start("myftp", client->getUser().c_str(), &localConversation,
                         &localAuthHandle);

  if (retval != PAM_SUCCESS) {
    return retval;
  }
  retval =
      pam_authenticate(localAuthHandle, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);

  if (retval != PAM_SUCCESS) {
    pam_end(localAuthHandle, retval);
    return retval;
  }

  retval = pam_acct_mgmt(localAuthHandle, PAM_DISALLOW_NULL_AUTHTOK);
  if (retval != PAM_SUCCESS) {
    pam_end(localAuthHandle, retval);
    return retval;
  }
  return pam_end(localAuthHandle, PAM_SUCCESS);
}

void closeData(std::shared_ptr<Session> client) {
  std::error_code ignored;
  if (client->passiveAcceptor) {
    client->passiveAcceptor->close(ignored);
    client->passiveAcceptor.reset();
  }
  auto data = client->getDataSock();
  if (data)
    data->close(ignored);
  client->setDataSock(nullptr);
  client->pendingDataCommand.reset();
  client->transferActive = false;
}

void closeSession(std::shared_ptr<Session> client) {
  client->closing = true;
  closeData(client);
  std::error_code ignored;
  client->getSock()->close(ignored);
}

void writeNextReply(std::shared_ptr<Session> client) {
  auto reply = client->replies.front();
  asio::async_write(*client->getSock(), asio::buffer(*reply.text),
                    [client, reply](asio::error_code ec, std::size_t) {
                      if (ec) {
                        std::clog << "Control reply failed: " << ec.message()
                                  << '\n';
                        client->replies.clear();
                        closeSession(client);
                        return;
                      }
                      client->replies.pop_front();
                      if (reply.afterSend)
                        reply.afterSend();
                      if (!client->closing && !client->replies.empty())
                        writeNextReply(client);
                    });
}

void asyncSendResponse(std::shared_ptr<std::string> response,
                       std::shared_ptr<Session> client,
                       std::function<void()> afterSend = {}) {
  if (client->closing)
    return;
  bool idle = client->replies.empty();
  client->replies.push_back({response, std::move(afterSend)});
  if (idle)
    writeNextReply(client);
}

void reply(std::shared_ptr<Session> client, const std::string &text) {
  asyncSendResponse(std::make_shared<std::string>(text), client);
}

// RFC 959 path quoting doubles embedded quotation marks.
std::string quotePath(const std::string &path) {
  std::string quoted = "\"";
  for (char c : path) {
    if (c == '"')
      quoted += '"';
    quoted += c;
  }
  return quoted + "\"";
}

std::pair<std::string, std::string> parseCommand(std::string line) {
  if (!line.empty() && line.back() == '\r')
    line.pop_back();
  auto space = line.find(' ');
  auto command = line.substr(0, space);
  std::transform(
      command.begin(), command.end(), command.begin(),
      [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return {command, space == std::string::npos ? "" : line.substr(space + 1)};
}

std::string LIST(std::string path) {
  std::string out;
  std::clog << "Listing directory: " << path << std::endl;
  for (auto entry : std::filesystem::directory_iterator(path)) {
    out.append(entry.path().string());
    out.append("\n");
  }
  return out;
}

void sendFile(std::shared_ptr<std::ifstream> file,
              std::shared_ptr<std::vector<uint8_t>> data,
              std::shared_ptr<asio::ip::tcp::socket> sock, std::size_t size,
              std::shared_ptr<Session> client) {
  if (size <= 0) {
    closeData(client);
    reply(client, "226 Transfer complete.\r\n");
    std::error_code ignored;
    sock->shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
    sock->close(ignored);

    return;
  }
  asio::async_write(
      *sock, asio::buffer(data->data(), size),
      [sock, data, size, file, client](asio::error_code ec, std::size_t) {
        if (ec) {
          closeData(client);
          reply(client, "426 Data connection failure; transfer aborted.\r\n");
          return;
        }
        file->read(reinterpret_cast<char *>(data->data()), data->size());
        if (file->bad()) {
          closeData(client);
          reply(client, "451 Cannot read source file.\r\n");
          return;
        }

        std::size_t n = static_cast<std::size_t>(file->gcount());
        sendFile(file, data, sock, n, client);
      });
}

// sock is the data socket, s is the command (LIST or RETR) that was received
// on the control connection

void readFile(std::shared_ptr<asio::ip::tcp::socket> sock,
              std::shared_ptr<std::ofstream> file,
              std::shared_ptr<std::vector<uint8_t>> dataBuffer,
              std::shared_ptr<Session> client) {

  asio::async_read(
      *sock, asio::buffer(dataBuffer->data(), dataBuffer->size()),
      [sock, file, dataBuffer, client](asio::error_code ec, std::size_t size) {
        if (ec && ec != asio::error::eof) {
          closeData(client);
          reply(client, "426 Data connection failure; transfer aborted.\r\n");
          return;
        }
        if (size > 0) {
          file->write(reinterpret_cast<char *>(dataBuffer->data()), size);
          if (!*file) {
            closeData(client);
            reply(client, "451 Cannot write uploaded file.\r\n");
            return;
          }
        }
        if (ec == asio::error::eof) {
          file->close();
          closeData(client);
          reply(client, file->fail() ? "451 Cannot finalize uploaded file.\r\n"
                                     : "226 Transfer complete.\r\n");
          return;
        }
        readFile(sock, file, dataBuffer, client);
      });
}

void newSock(std::shared_ptr<Session> client, std::shared_ptr<std::string> s) {
  auto path = client->getPath();
  auto parsed = parseCommand(*s);
  if ((parsed.first == "RETR" || parsed.first == "STOR") &&
      parsed.second.empty()) {
    closeData(client);
    reply(client, "501 Missing pathname.\r\n");
    return;
  }
  std::clog << "Data command: " << *s << "\n";
  if (parsed.first == "LIST") {
    reply(client, "150 Starting directory listing.\r\n");
    try {
      *s = LIST(*path);
    } catch (const std::exception &e) {
      std::clog << "Listing failed: " << e.what() << '\n';
      closeData(client);
      reply(client, "550 Directory listing unavailable.\r\n");
      return;
    }
    auto sock2 = client->getDataSock();
    asio::async_write(
        *sock2, asio::buffer(s->data(), s->size()),
        [sock2, s, client](asio::error_code ec, std::size_t) {
          if (ec) {
            closeData(client);
            reply(client, "426 Data connection failure; transfer aborted.\r\n");
            return;
          }
          std::error_code ignored;
          sock2->shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
          sock2->close(ignored);
          closeData(client);
          reply(client, "226 Directory listing complete.\r\n");
          return;
        });
  } else if (parsed.first == "RETR") {

    std::string name = (std::filesystem::path(*path) / parsed.second).string();
    while (name.size() > 0 && (name.at(name.size() - 1) == '\r' ||
                               name.at(name.size() - 1) == '\n')) {
      name.pop_back();
    }
    auto file = std::make_shared<std::ifstream>(name, std::ios::binary);
    if (!*file) {
      closeData(client);
      reply(client, "550 Cannot open source file.\r\n");
      return;
    }
    reply(client, "150 Starting file download.\r\n");
    auto data = std::make_shared<std::vector<uint8_t>>(20 * 1024);
    file->read(reinterpret_cast<char *>(data->data()), data->size());
    if (file->bad()) {
      closeData(client);
      reply(client, "451 Cannot read source file.\r\n");
      return;
    }
    sendFile(file, data, client->getDataSock(),
             static_cast<std::size_t>(file->gcount()), client);
  } else if (parsed.first == "STOR") {

    std::string name = (std::filesystem::path(*path) / parsed.second).string();
    while (name.size() > 0 && (name.at(name.size() - 1) == '\r' ||
                               name.at(name.size() - 1) == '\n')) {
      name.pop_back();
    }
    auto file = std::make_shared<std::ofstream>(name, std::ios::binary);
    if (!*file) {
      closeData(client);
      reply(client, "550 Cannot open destination file.\r\n");
      return;
    }
    reply(client, "150 Starting file upload.\r\n");
    auto dataBuffer = std::make_shared<std::vector<uint8_t>>(20 * 1024);
    readFile(client->getDataSock(), file, dataBuffer, client);
  }
}

void newSock(std::shared_ptr<Session>, std::shared_ptr<std::string>);

void dataTCP(std::shared_ptr<asio::ip::tcp::acceptor> acpt,
             std::shared_ptr<Session> client) {
  auto sock2 = std::make_shared<asio::ip::tcp::socket>(context);
  acpt->async_accept(*sock2, [sock2, acpt, client](std::error_code ec) {
    if (ec)
      return;
    if (client->closing)
      return;
    std::clog << "Data connection accepted\n";
    acpt->close();
    client->setDataSock(sock2);
    client->passiveAcceptor.reset();
    if (client->pendingDataCommand) {
      auto cmd = client->pendingDataCommand;
      client->pendingDataCommand.reset();
      newSock(client, cmd);
    }
  });
}
void handleCommands(std::shared_ptr<Session> client) {
  if (client->closing)
    return;
  std::clog << "Waiting for control command\n";
  asio::async_read_until(
      *(client->getSock()), client->controlBuffer, "\r\n",
      [client](std::error_code ec, std::size_t) {
        std::shared_ptr<asio::ip::tcp::socket> sock = client->getSock();
        std::shared_ptr<std::string> path = client->getPath();

        if (ec) {
          closeSession(client);
          return;
        }

        std::istream is(&client->controlBuffer);

        std::string response;
        std::getline(is, response);
        auto parsed = parseCommand(response);
        if (!response.empty() && response.back() == '\r')
          response.pop_back();
        const auto &command = parsed.first;
        if (client->transferActive && command != "QUIT") {
          reply(client, "450 Transfer in progress.\r\n");
          handleCommands(client);
          return;
        }

        if (command == "QUIT") {
          asyncSendResponse(std::make_shared<std::string>("221 Goodbye.\r\n"),
                            client, [client] { closeSession(client); });
          return;
        }

        if (client->getCurrent() == RENAME) {
          std::clog << "Rename destination received; source: "
                    << client->getPastFile() << "\n";
          client->setCurrent(NONE);
          if (!ec) {
            while (response.size() > 0 &&
                   (response.at(response.size() - 1) == '\r' ||
                    response.at(response.size() - 1) == '\n')) {
              response.pop_back();
            }
            auto pos = response.find(' ');
            if (pos != std::string::npos && pos < response.size() - 1) {

              std::string comm = response.substr(0, pos),
                          file = response.substr(pos + 1);
              std::error_code ec;
              if (comm == "RNTO") {
                std::filesystem::rename(client->getPastFile(),
                                        *(client->getPath()) + '/' + file, ec);
                if (!ec) {
                  auto sting = std::make_shared<std::string>(
                      "250 Rename successful.\r\n");
                  asyncSendResponse(sting, client);
                } else {

                  auto sting =
                      std::make_shared<std::string>("550 Rename failed.\r\n");
                  asyncSendResponse(sting, client);
                }
              } else {

                auto sting = std::make_shared<std::string>(
                    "503 Expected RNTO after RNFR.\r\n");
                asyncSendResponse(sting, client);
              }
            } else {

              auto sting = std::make_shared<std::string>(
                  "501 Missing rename destination.\r\n");
              asyncSendResponse(sting, client);
            }
          }

        }

        else if ((command == "LIST" || command == "RETR" ||
                  command == "STOR")) {
          while (response.size() > 0 &&
                 (response.at(response.size() - 1) == '\r' ||
                  response.at(response.size() - 1) == '\n')) {
            response.pop_back();
          }
          auto cmd = std::make_shared<std::string>(response);
          if (!client->getDataSock() && !client->passiveAcceptor) {
            reply(client, "425 Use PASV before a transfer.\r\n");
          } else {
            client->transferActive = true;
            if (client->getDataSock())
              newSock(client, cmd);
            else
              client->pendingDataCommand = cmd;
          }
        }

        else if (command == "PASV") {
          std::clog << "Control command: " << response << "\n";
          closeData(client);
          auto accept = std::make_shared<asio::ip::tcp::acceptor>(
              context,
              asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
          auto port = accept->local_endpoint().port();
          auto oct = sock->local_endpoint().address().to_v4().to_bytes();
          auto response = std::make_shared<std::string>(
              "227 Entering Passive Mode (" + std::to_string(oct[0]) + "," +
              std::to_string(oct[1]) + "," + std::to_string(oct[2]) + "," +
              std::to_string(oct[3]) + "," + std::to_string(port / 256) + "," +
              std::to_string(port % 256) + ")\r\n");
          asyncSendResponse(response, client);
          client->passiveAcceptor = accept;
          dataTCP(accept, client);
        } else if (command == "CWD") {
          if (parsed.second.empty())
            reply(client, "501 Missing pathname.\r\n");
          else {
            std::error_code error;
            auto destination = (std::filesystem::path(*path) / parsed.second)
                                   .lexically_normal();
            if (std::filesystem::is_directory(destination, error) && !error) {
              *path = destination.string();
              reply(client, "250 Directory changed.\r\n");
            } else
              reply(client, "550 Directory unavailable.\r\n");
          }
        } else if (command == "PWD") {

          auto response = std::make_shared<std::string>(
              "257 " + quotePath(*path) + " is the current directory.\r\n");
          asyncSendResponse(response, client);
        } else if ((command == "MKD" || command == "MKDIR")) {
          auto pos = response.find(" ");
          if (pos != std::string::npos) {
            std::string next = response.substr(pos + 1);

            if (!next.empty()) {
              std::string brandNew;
              if (next != *path) {
                brandNew = *path + '/' + next;

              } else
                brandNew = next;
              std::error_code ec2;
              bool created = std::filesystem::create_directory(brandNew, ec2);
              if (!ec2 && created) {
                reply(client, "257 " + quotePath(brandNew) + " created.\r\n");
              } else {
                reply(client, "550 Cannot create directory.\r\n");
              }
            } else
              reply(client, "501 Missing pathname.\r\n");
          } else {
            reply(client, "501 Missing pathname.\r\n");
          }
        } else if (command == "DELE" || command == "RMD") {
          auto pos = response.find(" ");
          if (pos != std::string::npos) {
            std::string next = response.substr(pos + 1);

            if (!next.empty()) {

              std::string brandNew;
              if (next != *path) {
                brandNew = *path + '/' + next;

              } else
                brandNew = next;
              std::error_code ec2;
              bool removed = std::filesystem::remove(brandNew, ec2);

              if (!ec2 && removed) {
                reply(client, "250 Deletion successful.\r\n");
              } else {
                reply(client, "550 Cannot delete pathname.\r\n");
              }
            } else
              reply(client, "501 Missing pathname.\r\n");
          } else {
            reply(client, "501 Missing pathname.\r\n");
          }
        } else if (command == "RNFR") {
          auto pos = response.find(" ");
          std::clog << "RNFR received\n";
          if (pos != std::string::npos) {
            std::string next = response.substr(pos + 1);

            if (!next.empty()) {
              std::string source = *(client->getPath()) + '/' + next;
              std::error_code lookupError;
              if (std::filesystem::exists(source, lookupError) &&
                  !lookupError) {
                reply(client, "350 Source accepted; send RNTO.\r\n");
                client->setPastFile(source);
                client->setCurrent(RENAME);
              } else {
                reply(client, "550 Rename source unavailable.\r\n");
              }
            } else {
              reply(client, "501 Missing pathname.\r\n");
            }
          } else {
            reply(client, "501 Missing pathname.\r\n");
          }
        } else {
          reply(client, "502 Command not implemented.\r\n");
        }
        handleCommands(client);
      });
}

void inicialUser(std::shared_ptr<Session> client) {
  if (client->closing)
    return;
  asio::async_read_until(
      *client->getSock(), client->controlBuffer, "\r\n",
      [client](asio::error_code ec, std::size_t) {
        if (ec) {
          closeSession(client);
          return;
        }
        std::istream input(&client->controlBuffer);
        std::string line;
        std::getline(input, line);
        auto [command, argument] = parseCommand(line);
        if (command == "QUIT") {
          asyncSendResponse(std::make_shared<std::string>("221 Goodbye.\r\n"),
                            client, [client] { closeSession(client); });
          return;
        }
        if (command == "USER") {
          if (argument.empty())
            reply(client, "501 Missing user name.\r\n");
          else {
            client->setUser(argument);
            client->setCurrent(PASS);
            reply(client, "331 User name accepted; password required.\r\n");
          }
        } else if (command == "PASS" && client->getCurrent() == PASS) {
          client->setPass(argument);
          client->getPassword().clearPrompt();
          int status = pamAutenticateUser(client, std::nullopt);
          client->setPass("");
          client->getPassword().clearPrompt();
          if (status == PAM_SUCCESS) {
            client->setCurrent(NONE);
            client->setAuth(true);
            auto *account = getpwnam(client->getUser().c_str());

            if (!account || !account->pw_dir || account->pw_dir[0] == '\0') {
              std::cout << "faliure getting home directory\n";
              return;
            }
            client->setPath(account->pw_dir);

            reply(client, "230 Login successful.\r\n");
            handleCommands(client);
            return;
          }
          std::clog << "PAM login failed with status " << status << '\n';
          client->setCurrent(USER);
          reply(client, "530 Login incorrect.\r\n");
        } else {
          reply(client, command == "PASS"
                            ? "503 Send USER first.\r\n"
                            : "530 Please log in with USER and PASS.\r\n");
        }
        inicialUser(client);
      });
}

void getConnection(std::shared_ptr<asio::ip::tcp::acceptor> acept) {
  auto path = std::shared_ptr<std::string>();
  auto sock = std::make_shared<asio::ip::tcp::socket>(context);
  auto client = std::make_shared<Session>(sock, path);
  client->setCurrent(USER);
  acept->async_accept(*sock, [client, acept](std::error_code ec) {
    std::clog << "Control accept completed\n";
    if (ec)
      return;
    reply(client, "220 FTP service ready.\r\n");
    inicialUser(client);

    // buf is a dynamic buffer
    getConnection(acept);
  });
}

int main() {
  if (sodium_init() < 0) {
    std::cerr << "Could not initialize libsodium\n";
    return 1;
  }

  auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(
      context,
      asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 2121));
  std::clog << "FTP server listening on 127.0.0.1:2121\n";

  getConnection(acceptor);
  context.run();
}

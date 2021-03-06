#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

void decrypt(char[], unsigned long, const char[]);
void error(const char*);
void receiveStringFromSocket(const int*, char[], char[], const int*, const char[]);
void sendStringToSocket(const int*, const char[]);

int main(int argc, char* argv[]) {
  int listenSocketFD, establishedConnectionFD, portNumber;
  socklen_t sizeOfClientInfo;
  struct sockaddr_in serverAddress, clientAddress;
  int bufferSize = 150000, messageFragmentSize = 10;
  char buffer[bufferSize], messageFragment[messageFragmentSize];
  unsigned long decryptedMessageLength = 0;
  char* keyRead = NULL;
  char connectionValidator[] = "<<";
  char endOfMessage[] = "||";
  char invalidError[] = "Received an incoming connection from an unknown source.";
  int exitMethod = -5;
  pid_t spawnPid = -5;

  // Check usage & args
  if (argc < 2) {
    fprintf(stderr, "Correct command format: %s PORT\n", argv[0]);
    exit(1);
  }

  // Set up the address struct for this process (the server)
  memset((char *) &serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
  portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
  serverAddress.sin_family = AF_INET; // Create a network-capable socket
  serverAddress.sin_port = htons(portNumber); // Store the port number
  serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

  // Set up the socket
  listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocketFD < 0)
    error("An error occurred opening a socket");

  // Enable the socket to begin listening
  if (bind(listenSocketFD, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) < 0)
    error("An error occurred binding to a socket");

  // Flip the socket on - it can now receive up to 5 connections
  listen(listenSocketFD, 5);

  // Create an infinite loop so we can act like a daemon
  while (1) {
    // Get the size of the address for the client that will connect
    sizeOfClientInfo = sizeof(clientAddress);
    // Accept a connection, blocking if one is not available until one connects
    establishedConnectionFD = accept(listenSocketFD, (struct sockaddr*) &clientAddress, &sizeOfClientInfo);

    // Fork a new process for the accepted connection if we didn't detect an error
    spawnPid = fork();
    switch (spawnPid) {

      case -1:
        error("An error occurred creating a process to handle a new connection");

      case 0:
        if (establishedConnectionFD < 0)
          error("An error occurred accepting a connection");

        // Clear the buffer to receive a message from the client
        memset(buffer, '\0', bufferSize);

        // Read the client's handshake message from the socket
        receiveStringFromSocket(&establishedConnectionFD, buffer, messageFragment, &messageFragmentSize, endOfMessage);

        if (strcmp(buffer, connectionValidator) != 0) {
          // Send back an error message if the wrong program is trying to connect to our daemon
          sendStringToSocket(&establishedConnectionFD, invalidError);
          sendStringToSocket(&establishedConnectionFD, endOfMessage);
        } else {
          // Send back the connection validator and end of message string if the connection came from otp_dec
          sendStringToSocket(&establishedConnectionFD, "<<||");
        }

        // Prepare the buffer and receive the full encrypted message and key from the client
        memset(buffer, '\0', sizeof(buffer));
        receiveStringFromSocket(&establishedConnectionFD, buffer, messageFragment, &messageFragmentSize, endOfMessage);

        /* Our key in the buffer begins after the newline character at the end of the ciphertext message,
         * so we set keyRead to the index in the buffer directly after the new line, then exit our loop. */
        for (size_t i = 0; i < strlen(buffer); i++) {
          if (buffer[i] == '\n') {
            keyRead = buffer + i + 1;
            break;
          }
        }
        /* Once we've found the location of the key, we know that the length of the message is the length of the full
         * buffer minus the length of the key and the newline character. */
        decryptedMessageLength = strlen(buffer) - strlen(keyRead) - 1;

        /* Verify that the length of the key (minus the newline character) was long enough for us to decrypt the
         * ciphertext message. Otherwise, print an error. */
        if ((strlen(keyRead) - 1) >= decryptedMessageLength) {
          decrypt(buffer, decryptedMessageLength, keyRead);
          sendStringToSocket(&establishedConnectionFD, buffer);
          sendStringToSocket(&establishedConnectionFD, endOfMessage);
        } else {
          fprintf(stderr, "The provided key must have at least %lu characters to decrypt the provided message.\n", decryptedMessageLength);
        }

        // Close the existing socket which is connected to the client
        close(establishedConnectionFD);

      default:
        // Try to reap any zombie child processes
        spawnPid = waitpid(-1, &exitMethod, WNOHANG);
        // Close the existing socket which is connected to the client
        close(establishedConnectionFD);
    }


  }
  // Close the listening socket
  close(listenSocketFD);
  return(0);
}

/* Takes a string, the string's message length, and a key, then translates the ASCII value of each character
 * into a number between 0 and 26. The message character's value is subtracted by the key character's value
 * (adding 27 if we get a negative result from subtraction) then modular arithmetic decrypts the result.
 * Finally, we translate each character back into an ASCII value and add a null terminator to the end of the string. */
void decrypt(char message[], const unsigned long messageLength, const char key[]) {
  int ciphertextValue = -1, keyValue = -1, decryptedValue = -1;

  for (size_t i = 0; i < messageLength; i++) {
    /* Adjust spaces to equal the last value in our range, 26, so we can properly calculate the decrypted value with
     * modular arithmetic. */
    if ((int) message[i] == 32)
      ciphertextValue = 26;
    else
      ciphertextValue = (int) (message[i] - 65);

    if ((int) key[i] == 32)
      keyValue = 26;
    else
      keyValue = (int) (key[i] - 65);

    decryptedValue = ciphertextValue - keyValue;
    if (decryptedValue < 0)
      decryptedValue += 27;
    decryptedValue %= 27;

    if (decryptedValue == 26)
      message[i] = (char) 32;
    else
      message[i] = (char) (decryptedValue + 65);
  }
  message[messageLength] = '\0';
}

// Error function used for reporting issues
void error(const char* msg) {
  perror(msg);
  exit(1);
}

/* Takes a socket, a message buffer, a smaller array to hold characters as they're read, the size of the array, and a
 * small string used by client and server to indicate the end of a message. The function loops through until the
 * substring is found, as seen in the Network Clients video for block 4, repeatedly adding the message fragment
 * to the end of the message. The substring that marks the end of the message is then replaced with a null terminator. */
void receiveStringFromSocket(const int* establishedConnectionFD, char message[], char messageFragment[], const int* messageFragmentSize, const char endOfMessage[]) {
  int charsRead = -5;
  long terminalLocation = -5;

  while (strstr(message, endOfMessage) == NULL) {
    memset(messageFragment, '\0', *messageFragmentSize);
    charsRead = recv(*establishedConnectionFD, messageFragment, *messageFragmentSize - 1, 0);

    // Exit the loop if we either don't read any more characters when receiving, or we failed to retrieve any characters
    if (charsRead == 0)
      break;
    if (charsRead == -1)
      break;

    strcat(message, messageFragment);
  }

  /* Find the terminal location using the method in the Network Clients video from Block 4
   * then set a null terminator after the actual message contents end. */
  terminalLocation = strstr(message, endOfMessage) - message;
  message[terminalLocation] = '\0';
}

/* Takes a pointer to a socket, followed by a string to send via that socket,
 * then loops to ensure all the data in the string is sent. */
void sendStringToSocket(const int* socketFD, const char message[]) {
  int charsWritten;
  // Send message to server
  charsWritten = send(*socketFD, message, strlen(message), 0); // Write to the server
  if (charsWritten < 0)
    error("An error occurred writing to the socket");

  while (charsWritten < strlen(message)) {
    int addedChars = 0;
    // Write to the server again, starting from one character after the most recently sent character
    addedChars = send(*socketFD, message + charsWritten, strlen(message) - charsWritten, 0);
    if (addedChars < 0)
      error("An error occurred writing to the socket");

    // Exit the loop if no more characters are being sent to the server.
    if (addedChars == 0) {
      break;
    }

    // Add the number of characters written in an iteration to the total number of characters sent in the message
    charsWritten += addedChars;
  }
}

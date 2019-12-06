#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(0);
}

int main(int argc, char *argv[]) {
  int socketFD, portNumber, charsWritten, charsRead;
  int plaintextFD, plaintextLength, keyFD, keyLength;
  struct sockaddr_in serverAddress;
  struct hostent* serverHostInfo;
  int bufferSize = 75000;
  char buffer[bufferSize];
  char stringValidator[2];
  char connectionValidator[] = ">>";
  char endOfMessage[] = "||";

  // Check usage & args
  if (argc < 4) {
    fprintf(stderr, "Correct command format: %s PLAINTEXT KEY PORT\n", argv[0]);
    exit(1);
  }

  // Set up the server address struct
  memset((char*) &serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
  portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
  serverAddress.sin_family = AF_INET; // Create a network-capable socket
  serverAddress.sin_port = htons(portNumber); // Store the port number
  serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address

  if (serverHostInfo == NULL) {
    fprintf(stderr, "An error occurred defining a server address.\n");
    exit(0);
  }
  memcpy((char*) &serverAddress.sin_addr.s_addr, (char*) serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

  // Set up the socket
  socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
  if (socketFD < 0)
    error("An error occurred creating a socket");

  // Connect to server
  if (connect(socketFD, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
    error("An error occurred connecting to the server");

  // Send message to server
  charsWritten = send(socketFD, connectionValidator, strlen(connectionValidator), 0); // Write to the server
  if (charsWritten < 0)
    error("An error occurred writing to the socket");

  while (charsWritten < strlen(connectionValidator)) {
    int addedChars = 0;
    // Write to the server again, starting from one character after the most recently sent character
    addedChars = send(socketFD, connectionValidator + charsWritten, strlen(connectionValidator) - charsWritten, 0);
    if (addedChars < 0)
      error("An error occurred writing to the socket");

    // Exit the loop if no more characters are being sent to the server.
    if (addedChars == 0) {
      break;
    }

    // Add the number of characters written in an iteration to the total number of characters sent in the message
    charsWritten += addedChars;
  }

  // Get return message from server
  memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer
  charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
  if (charsRead < 0)
    error("An error occurred reading from the socket");

  if (strcmp(buffer, connectionValidator) != 0) {
    fprintf(stderr, "A connection was made to an unknown destination.\n");
    exit(1);
  } else {

    /* Open the specified plaintext and key files, checking for existence and setting the length of each file in
     * bytes so we can verify the key we'll send to the daemon is long enough to encrypt the plaintext message. */
    plaintextFD = open(argv[1], O_RDONLY);
    if (plaintextFD < 0)
      error("Could not open the specified plaintext file");
    /* Set the length equal to the size of the file
     * (source: https://stackoverflow.com/questions/174531/how-to-read-the-content-of-a-file-to-a-string-in-c). */
    plaintextLength = lseek(plaintextFD, 0, SEEK_END) - 1;

    // Repeat the above steps for our key to get its size.
    keyFD = open(argv[2], O_RDONLY);
    if (keyFD < 0)
      error("Could not open the specified key file");
    keyLength = lseek(keyFD, 0, SEEK_END) - 1;

    // Print an error message and exit if the key is too short to use.
    if (keyLength < plaintextLength) {
      fprintf(stderr, "The provided key does not meet the minimum length requirements to "
                      "encrypt your message.\nPlease provide a key with a length of %d or more.\n", plaintextLength);
      exit(1);
    }

    memset(stringValidator, '\0', sizeof(stringValidator));
    lseek(plaintextFD, 0, SEEK_SET);
    while (read(plaintextFD, stringValidator, 1) != 0) {
      if (!isupper(stringValidator[0]) && !isspace(stringValidator[0])) {
        fprintf(stderr, "One or more invalid characters were supplied in the plaintext message: %c.\n", stringValidator[0]);
        exit(1);
      }
    }

    // Get input message from user
    printf("CLIENT: Enter text to send to the server, and then hit enter: ");
    memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array
    fgets(buffer, sizeof(buffer) - 1, stdin); // Get input from the user, trunc to buffer - 1 chars, leaving \0
    buffer[strcspn(buffer, "\n")] = '\0'; // Remove the trailing \n that fgets adds

    // Send message to server
    charsWritten = send(socketFD, buffer, strlen(buffer), 0); // Write to the server
    if (charsWritten < 0)
      error("An error occurred writing to the socket");

    while (charsWritten < strlen(buffer)) {
      int addedChars = 0;
      // Write to the server again, starting from one character after the most recently sent character
      addedChars = send(socketFD, buffer + charsWritten, strlen(buffer) - charsWritten, 0);
      if (addedChars < 0)
        error("An error occurred writing to the socket");

      // Exit the loop if no more characters are being sent to the server.
      if (addedChars == 0) {
        break;
      }

      // Add the number of characters written in an iteration to the total number of characters sent in the message
      charsWritten += addedChars;
    }

    // Get return message from server
    memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
    if (charsRead < 0)
      error("An error occurred reading from the socket");
    fprintf(stdout, "%s\n", buffer);
  }

  close(socketFD); // Close the socket

  return(0);
}

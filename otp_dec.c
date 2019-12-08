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

void error(const char* msg);
void fileToBuffer(const int*, char[], const int*);
void receiveStringFromSocket(const int*, char[], char[], const int*, const char[]);
void sendStringToSocket(const int*, const char[]);
int isValidString(const char[]);

int main(int argc, char *argv[]) {
  int socketFD, portNumber;
  int ciphertextFD, ciphertextLength, keyFD, keyLength;
  int validText = 0, validKey = 0;
  struct sockaddr_in serverAddress;
  struct hostent* serverHostInfo;
  int bufferSize = 150000, messageFragmentSize = 10;
  char buffer[bufferSize], messageFragment[messageFragmentSize];
  char connectionValidator[] = "<<";
  char endOfMessage[] = "||";

  // Check usage & args
  if (argc < 4) {
    fprintf(stderr, "Correct command format: %s CIPHERTEXT KEY PORT\n", argv[0]);
    exit(2);
  }

  /* Open the specified ciphertext and key files, checking for existence and setting the length of each file in
   * bytes so we can verify the key we'll send to the daemon is long enough to decrypt the ciphertext message. */
  ciphertextFD = open(argv[1], O_RDONLY);
  if (ciphertextFD < 0)
    error("Could not open the specified ciphertext file");
  /* Set the length of the provided ciphertext equal to the size of the file
   * (source: https://stackoverflow.com/questions/174531/how-to-read-the-content-of-a-file-to-a-string-in-c). */
  ciphertextLength = lseek(ciphertextFD, 0, SEEK_END);

  // Repeat the above steps for our key to get its size.
  keyFD = open(argv[2], O_RDONLY);
  if (keyFD < 0)
    error("Could not open the specified key file");
  keyLength = lseek(keyFD, 0, SEEK_END);

  // Print an error message and exit if the key is too short to use.
  if (keyLength < ciphertextLength) {
    fprintf(stderr, "The provided key does not meet the minimum length requirements to "
                    "decrypt your message.\nPlease provide a key with a length of %d or more.\n", ciphertextLength - 1);
    close(ciphertextFD);
    close(keyFD);
    exit(1);
  }

  /* Store the encrypted message in our buffer, then pass the buffer to isValidString to make sure that the message has
 * characters that can be decrypted */
  memset(buffer, '\0', sizeof(buffer));
  fileToBuffer(&ciphertextFD, buffer, &ciphertextLength);
  validText = isValidString(buffer);

  /* Store the key in our buffer, then pass the buffer to isValidString to make sure that the message has
* characters that can be used to decrypt our message */
  memset(buffer, '\0', sizeof(buffer));
  fileToBuffer(&keyFD, buffer, &keyLength);
  validKey = isValidString(buffer);

  // Print an error message and exit before attempting to connect if either the message or key were invalid
  if (!validText || !validKey) {
    fprintf(stderr, "One or more invalid characters were detected.\n");
    close(ciphertextFD);
    close(keyFD);
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
    exit(2);
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
  sendStringToSocket(&socketFD, "<<||");

  // Get return message from server
  memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer
  receiveStringFromSocket(&socketFD, buffer, messageFragment, &messageFragmentSize, endOfMessage);

  if (strcmp(buffer, connectionValidator) != 0) {
    // Close the socket and clean up since the message received suggests this wasn't the right daemon
    close(socketFD);
    // Close file descriptors
    close(ciphertextFD);
    close(keyFD);
    fprintf(stderr, "A connection was made to an unknown destination.\n");
    exit(2);
  } else {
    // Send the ciphertext by storing it in the cleared buffer, closing the file descriptor and sending it through the socket
    memset(buffer, '\0', sizeof(buffer));
    fileToBuffer(&ciphertextFD, buffer, &ciphertextLength);
    close(ciphertextFD);
    sendStringToSocket(&socketFD, buffer);

    // Send the key by storing it in the cleared buffer, closing the file descriptor and sending it through the socket
    memset(buffer, '\0', sizeof(buffer));
    fileToBuffer(&keyFD, buffer, &keyLength);
    close(keyFD);
    sendStringToSocket(&socketFD, buffer);

    // Indicate to the server that both the ciphertext and key have been sent
    sendStringToSocket(&socketFD, endOfMessage);

    // Get return message from server
    memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
    receiveStringFromSocket(&socketFD, buffer, messageFragment, &messageFragmentSize, endOfMessage);

    // Output the decrypted result to stdout
    fprintf(stdout, "%s\n", buffer);
  }

  close(socketFD); // Close the socket

  return(0);
}

// Error function used for reporting issues
void error(const char* msg) {
  perror(msg);
  exit(2);
}

/* Takes a file descriptor pointer, a buffer to store the file's contents and a pointer to the length of the file,
 * then uses the read function to store the provided number of bytes from the file into the buffer. */
void fileToBuffer(const int* fileDescriptor, char buffer[], const int* fileLength) {
  int bytesRead = -5;
  lseek(*fileDescriptor, 0, SEEK_SET);
  bytesRead = read(*fileDescriptor, buffer, *fileLength);
  if (bytesRead < 0)
    error("An error occurred trying to read file contents");
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
    if (addedChars == 0)
      break;

    // Add the number of characters written in an iteration to the total number of characters sent in the message
    charsWritten += addedChars;
  }
}

/* Takes a string, then uses a loop starting from the beginning of the string to check one character at a time,
 * ensuring that the character is either a space or uppercase letter. Exits the loop and returns true at the end
 * of the string, or returns false when an invalid character is found that can't be sent to our daemon. */
int isValidString(const char buffer[]) {
  for (int i = 0; i < strlen(buffer); i++) {
    if (!isupper(buffer[i]) && !isspace(buffer[i])) {
      return(0);
    }
  }
  return(1);
}

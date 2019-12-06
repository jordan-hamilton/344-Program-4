#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(1);
}

int main(int argc, char *argv[]) {
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
  int bufferSize = 75000, dataFragmentSize = 10;
	char buffer[bufferSize], dataFragment[dataFragmentSize];
  char connectionValidator[] = ">>";
  char endOfMessage[] = "||";
  char invalidError[] = "Received an incoming connection from an unknown source.";
  struct sockaddr_in serverAddress, clientAddress;
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
	if (bind(listenSocketFD, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0)
		error("An error occurred binding to a socket");

  // Flip the socket on - it can now receive up to 5 connections
	listen(listenSocketFD, 5);

	// Create an infinite loop so we can act like a daemon
	while (1) {
    // Get the size of the address for the client that will connect
    sizeOfClientInfo = sizeof(clientAddress);
    // Accept a connection, blocking if one is not available until one connects
    establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *) &clientAddress, &sizeOfClientInfo);
    if (establishedConnectionFD < 0)
      error("An error occurred accepting a connection");

    // Fork a new process for the accepted connection if we didn't detect an error
    spawnPid = fork();
    switch (spawnPid) {
      case -1:
        error("An error occurred creating a process to handle a new connection");
      case 0:
        // Get the message from the client
        memset(buffer, '\0', bufferSize);
        char* keyRead;

        // Read the client's message from the socket
        charsRead = recv(establishedConnectionFD, buffer, sizeof(buffer) - 1, 0);
        if (charsRead < 0)
          error("An error occurred reading from the socket");

        if (strcmp(buffer, connectionValidator) != 0) {
          // Send back an error message if the wrong program is trying to connect to our daemon
          charsRead = send(establishedConnectionFD, invalidError, sizeof(invalidError), 0);
          if (charsRead < 0)
            error("An error occurred writing to the socket");
        } else {
          // Send back the connection validator string if the connection came from otp_enc
          charsRead = send(establishedConnectionFD, connectionValidator, sizeof(connectionValidator), 0);
          if (charsRead < 0)
            error("An error occurred writing to the socket");
        }

        // Prepare the buffer to receive the full message from the client
        memset(buffer, '\0', sizeof(buffer));

        while (strstr(buffer, endOfMessage) == NULL) {
          memset(dataFragment, '\0', sizeof(dataFragment));
          charsRead = recv(establishedConnectionFD, dataFragment, sizeof(dataFragment) - 1, 0);
          if (charsRead == 0)
            break;
          if (charsRead == -1)
            break;
          strcat(buffer, dataFragment);

          printf("Received fragment: %s\nMessage so far: %s\n", dataFragment, buffer);
        }

        /* Find the terminal location using the method in the Network Clients video from Block 4
         * then set a null terminator after the actual message contents end. */
        int terminalLocation = strstr(buffer, endOfMessage) - buffer;
        buffer[terminalLocation] = '\0';
        printf("Complete Message: \"%s\"\n", buffer);


        // Close the existing socket which is connected to the client
        close(establishedConnectionFD);

      default:
        // Close the existing socket which is connected to the client
        close(establishedConnectionFD);
    }


	}
  // Close the listening socket
  close(listenSocketFD);
  return(0);

	printf("SERVER: I received this from the client: \"%s\"\n", buffer);

	// Send a Success message back to the client
	charsRead = send(establishedConnectionFD, "I am the server, and I got your message", 39, 0); // Send success back
	if (charsRead < 0)
	  error("ERROR writing to socket");

	close(establishedConnectionFD);
	close(listenSocketFD);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
  int keyLength = -1;
  char* key = NULL;
  srand(time(0));

  if (argc >= 2) {
    keyLength = atoi(argv[1]);
    if (keyLength > 0) {
      key = malloc((keyLength + 1) * sizeof(char));
      memset(key, '\0', keyLength + 1);

      for (size_t i = 0; i < keyLength; i++) {
        char random = (rand() % 27) + 65;
        if (random == 91)
          random = 32;
        key[i] = random;
      }

      fprintf(stdout, "%s\n", key);

      free(key);
      key = NULL;

    } else {
      fprintf(stderr, "Error: The provided key length is not valid.\nCorrect command format: %s KEYLENGTH\n", argv[0]);
      exit(1);
    }

  } else {
    fprintf(stderr, "Error: Missing a required argument.\nCorrect command format: %s KEYLENGTH\n", argv[0]);
    exit(1);
  }

  return(0);
}


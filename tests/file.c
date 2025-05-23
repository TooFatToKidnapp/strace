#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>

// sudo apt-get install gcc-multilib -y

int main () {

  printf("guess a number from 1-100\n");

  char buff[10];

  srand(time(NULL));
  const int number_to_guess = (rand() % 100) + 1;
  printf("input your guess\n");

  while (true) {
    bzero(buff, sizeof(buff));
    if (NULL == fgets(buff, 9, stdin)) {
      break;
    }
    int guess = atoi(buff);
    if (0 == guess) {
      fprintf(stderr, "[%s] is not a valid number\n", buff);
      continue;
    }

    if (guess == number_to_guess) {
      printf("Congrats you guessed correctly\n");
      break;
    } else if (guess < number_to_guess) {
      printf("[%d] too small\n", guess);
    } else {
      printf("[%d] too large\n", guess);
    }

  }

}

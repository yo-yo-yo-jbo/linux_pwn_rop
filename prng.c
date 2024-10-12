#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

void
prng()
{
	uint8_t buf[16] = { 0 };
	int strength = 0;
	int i = 0;

	for (;;)
	{
		printf("Enter PRNG strength for the next byte [1-16] or choose 0 to finish: ");
		if ((1 != scanf("%d", &strength)) || (0 > strength))
		{
			printf("Invalid PRNG strength.\n");
			return;
		}
		if (0 == strength)
		{
			return;
		}
		for (i = 0; i < strength; i++)
		{
			buf[i] = rand() & 0xFF;
		}
		printf("PRNG byte: %.2x\n", buf[strength-1]);
		printf("PRNG byte: %.2x\n", buf[strength]);
	}	
}

int
main()
{
	int choice = 0;
	srand(time(0));

	setvbuf(stdout, NULL, _IONBF, 0);

	printf("Welcome to the military-grade SuperPRNG [TM]!\n");
	for (;;)
	{
		// Implement menu
		printf("1. Generate repeated random bytes (two bytes at a time).\n");
		printf("2. Quit.\n");
		printf("Choice? ");
		if (1 != scanf("%d", &choice) || choice < 1 || choice >= 2)
		{
			printf(2 == choice ? "Quitting, thank you for using the military-grade SuperPRNG [TM]!\n" : "Menu error!\n");
			break;
		}

		// Get random
		prng();
	}

	return 0;
}

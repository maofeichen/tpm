#include <stdio.h>
#include <stdlib.h>

#define ROW 1024 
#define COL 1024

#define u32 unsigned int

int main(int argc, char const *argv[])
{
	u32 count = 0;
	u32* ary = (u32 *)malloc(sizeof(u32) * ROW * COL);

	for(int r = 0; r < ROW; r++) {
		for (int c = 0; c < COL; c++) {
			ary[r*ROW + c] = count;
			count++;
		}
	}

	// for(int r = 0; r < ROW; r++) {
	// 	for (int c = 0; c < COL; c++) {
	// 		printf("ary[%d][%d]:%u\n", r, c, ary[r*ROW + c]);
	// 	}
	// }
	free(ary);
	printf("free array\n");
	return 0;
}

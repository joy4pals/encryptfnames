#include <stdio.h>
int main(void)
{
	FILE *fp;
	fp = fopen("/tmp/sparse.txt", "w");
	fprintf(fp, "hello");
	fseek(fp, 50, SEEK_CUR);
	fprintf(fp, "world");
	fclose(fp);
	return 0;
}

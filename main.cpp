#include <stdio.h>
#include <omp.h>
#include "DS_timer.h"

#define threads 8
#define FILE_SIZE (1024*1024*32)

void Simple_transposition_Encryption(char *input, char *output, int num); // �ܼ� ��ġ ��ȣȭ(1Round)
void Simple_transposition_Decryption(char *input, char *output, int num); // �ܼ� ��ġ ��ȣȭ(1Round)
void Simple_Substitution_Encryption(char *input, char *output); // �ܼ� ġȯ ��ȣȭ(2Round)
void Simple_Substitution_Decryption(char *input, char *output); // �ܼ� ġȯ ��ȣȭ(2Round)
void Route_Transposition_Encryption(char *input, char *output); // ��� ġȯ ��ȣȭ(3Round)
void Route_Transposition_Decryption(char *input, char *output); // ��� ġȯ ��ȣȭ(3Round)
void Multiple_Single_Substitution_Encryption(char *input, char *output, char *key); // ���� ���� ġȯ ��ȣȭ(4Round)
void Multiple_Single_Substitution_Decryption(char *input, char *output, char *key); // ���� ���� ġȯ ��ȣȭ(4Round)
// ���ϱ׸� ȸ���� ��ȣȭ, ��ȣȭ(5Round) (parallel)
void Enigma_Parallel(char *input, char *output, char enigma_before_roter_lower[4][6][26], char enigma_before_roter_upper[4][6][26]);

char* plain_text1 = new char[FILE_SIZE]; // ��
char* plain_text2 = new char[FILE_SIZE]; // ���� ��ȣȭ�� ��ȣ��
char* plain_text3 = new char[FILE_SIZE]; // ��ȣ���� �ٽ� ��ȣȭ�� ��

char** route_array = new char*[FILE_SIZE];	// ��� ġȯ�� ����� 2���� �迭
int end_j=0; // ��� ġȯ���� ������ ����ġ�� ������ ����

char vigenere_table_lower[26][26]; // �����׸� �迭(�ҹ���)
char vigenere_table_upper[26][26]; // �����׸� �迭(�빮��)
void Vigenere_Value_Lower(char input_vigenere[26][26]); // �����׸� �� �ִ� �Լ�(�ҹ���)
void Vigenere_Value_Upper(char input_vigenere[26][26]); // �����׸� �� �ִ� �Լ�(�빮��)
void Vigenere_Print(char vigenere[26][26]);	// �����׸� �� ��� �Լ�
char key[20]; // ���� ���� ġȯ�� ����� Ű

// ȸ���� ��
char enigma_rotor_lower_serial[6][26]={
	{'e','k','m','f','l','g','d','q','v','z','n','t','o','w','y','h','x','u','s','p','a','i','b','r','c','j'},
	{'a','j','d','k','s','i','r','u','x','b','l','h','w','t','m','c','q','g','z','n','p','y','f','v','o','e'},
	{'b','d','f','h','j','l','c','p','r','t','x','v','z','n','y','e','i','w','g','a','k','m','u','s','q','o'},
	{'e','s','o','v','p','z','j','a','y','q','u','i','r','h','x','l','n','f','t','g','k','d','c','m','w','b'},
	{'v','z','b','r','g','i','t','y','u','p','s','d','n','h','l','x','a','w','m','j','q','o','f','e','c','k'},
	{'j','p','g','v','o','u','m','f','y','q','b','e','n','h','z','r','d','k','a','s','x','l','i','c','t','w'}
};
char enigma_rotor_upper_serial[6][26]={
	{'E','K','M','F','L','G','D','Q','V','Z','N','T','O','W','Y','H','X','U','S','P','A','I','B','R','C','J'},
	{'A','J','D','K','S','I','R','U','X','B','L','H','W','T','M','C','Q','G','Z','N','P','Y','F','V','O','E'},
	{'B','D','F','H','J','L','C','P','R','T','X','V','Z','N','Y','E','I','W','G','A','K','M','U','S','Q','O'},
	{'E','S','O','V','P','Z','J','A','Y','Q','U','I','R','H','X','L','N','F','T','G','K','D','C','M','W','B'},
	{'V','Z','B','R','G','I','T','Y','U','P','S','D','N','H','L','X','A','W','M','J','Q','O','F','E','C','K'},
	{'J','P','G','V','O','U','M','F','Y','Q','B','E','N','H','Z','R','D','K','A','S','X','L','I','C','T','W'}	
};
char enigma_rotor_lower_parallel[threads][6][26];
char enigma_rotor_upper_parallel[threads][6][26];
void Rotor_Value(); // ȸ���� �� ���� (��,�ҹ���),(Parallel)

char reflector_lower[26];
char reflector_upper[26];
void Reflector_Value_Lower(char refl[26]); // ���÷��Ϳ� �� �ִ� �Լ�(�ҹ���)
void Reflector_Value_Upper(char refl[26]); // ���÷��Ϳ� �� �ִ� �Լ�(�빮��)
void Reflector_print(char refl[26]);	// ���÷��� �� ��� �Լ�

int Rotor_Find_Start(char rotor[6][26], int rotor_num, int num); // ȸ���� �� ã�� �Լ�(�����ϴ� ����)
int Rotor_Find_Turn(char rotor[6][26], int rotor_num, int num); // ȸ���� �� ã�� �Լ�(���ƿ��� ����)
int Rotor_Find_Parallel_Start(char rotor[4][6][26], int rotor_num, int num, int tid);
int Rotor_Find_Parallel_Turn(char rotor[4][6][26], int rotor_num, int num, int tid);
int Reflector_Find(char refl[26], int num); // ���÷��� �� ã�� �Լ�

void Version1();

void main(){

	FILE *input = fopen("input.txt","r");
	FILE *ciphertext = fopen("ciphertext.txt","w");
	FILE *output = fopen("output.txt","w");

	DS_timer timer(4);
	timer.initTimers();

	/*
	// ��� ġȯ���� ����� �迭 �Ҵ�
	for(int i = 0; i<FILE_SIZE; i++)
		route_array[i] = new char[4];
	*/

	/*
	// �����׸� �� �ֱ�
	Vigenere_Value_Lower(vigenere_table_lower);
	Vigenere_Value_Upper(vigenere_table_upper);
	// �����׸� Ȯ��
	Vigenere_Print(vigenere_table_lower);
	printf("Ű�� �Է��ϼ���: ");
	scanf("%s",key);	 // ���� ġȯ���� ����� Ű
	*/

	for(int i=0; i<26; i++)
		printf("[%2c]",'a'+i);
	printf("\n\n");

	// Roter �� ����
	Rotor_Value();

	// Reflector �� ���� �� ���
	Reflector_Value_Lower(reflector_lower);
	Reflector_Value_Upper(reflector_upper);
	Reflector_print(reflector_lower);

	/*
	// Ű����� �Է¹ޱ�
	printf("\n\n��ȣȭ�� ���� �Է��ϼ���.\n\n");	
	fgets(plain_text1, sizeof(plain_text1),stdin); // ��� ���ڿ� �� ����(����, ����, ����, ���๮��(enter))
	plain_text1[strlen(plain_text1)-1]=NULL;	 // ���๮�� NULL�����
	*/
	
	// Version 1
	// ���Ϸ� �Է¹ޱ�
	int num = fread(plain_text1, 1, FILE_SIZE, input);
	printf("\n\ninput size : %d\n", num);
	timer.onTimer(0);
	Version1();
	timer.offTimer(0);
	fwrite(plain_text2, 1, num, ciphertext);
	fwrite(plain_text3, 1, num, output);

	// Version 2
	timer.onTimer(0);
	
	timer.offTimer(0);

	// Version 3
	timer.onTimer(0);
	
	timer.offTimer(0);

	// Version 4
	timer.onTimer(0);
	
	timer.offTimer(0);
	
	timer.printTimer();
}
void Version1(){
//	printf("\n\n\n%s\n", plain_text1);

	Enigma_Parallel(plain_text1, plain_text2, enigma_rotor_lower_parallel, enigma_rotor_upper_parallel);
	
//	printf("\n\n%s\n", plain_text2);
	
	Enigma_Parallel(plain_text2, plain_text3, enigma_rotor_lower_parallel, enigma_rotor_upper_parallel);

//	printf("\n\n%s\n", plain_text3);
}

// �ܼ� ��ġ ��ȣȭ(1Round)
void Simple_transposition_Encryption(char *input, char *output, int num) {
	for(int i=0; i<strlen(input); i++)
		output[ (i+num) % (strlen(input)) ] = input[i];
}

// �ܼ� ��ġ ��ȣȭ(1Round)
void Simple_transposition_Decryption(char *input, char *output, int num) {
	for(int i=0; i<strlen(input); i++)
		output[ (i+strlen(input)-num) % (strlen(input)) ] = input[i];
}

// �ܼ� ġȯ ��ȣȭ(2Round)
void Simple_Substitution_Encryption(char *input, char *output){
	// 3 ��� � ������ ���� �����ص� ����(�� 3 x + 5 (mod 26))
	for(int i=0; i<strlen(input); i++)
		output[i] = input[i] + 3;
}

// �ܼ� ġȯ ��ȣȭ(2Round)
void Simple_Substitution_Decryption(char *input, char *output){
	// 3 ��� � ������ ���� �����ص� ����(�� 3 x + 5 (mod 26))
	for(int i=0; i<strlen(input); i++)
		output[i] = input[i] - 3;
}

// ��� ġȯ ��ȣȭ(3Round)
void Route_Transposition_Encryption(char *input, char *output){
	int j=0, k=0; // 2���� �迭�� ���� ����

	int count=0; // 4��° ���� j(��)�� ���������� �ѱ� ����

	// input���� 2���� �迭�� [n][4]�� ���� ���ʴ�� �ֱ�
	for(int i=0; i<strlen(input); i++, k++, count++){
		k=k%4;
		j=count/4;
		route_array[j][k]=input[i];
	}
	end_j=j+1;
	j=0, k=0, count=0;

	// 2���� �迭 [n][4]�� ���� 1��,2��,3��... ������ ���� ouput�� �ֱ�
	for(int i=0; i<strlen(input); i++, j++,count++){
		j=j%end_j;
		k=count/end_j;
		output[i]=route_array[j][k];
	}
}

// ��� ġȯ ��ȣȭ(3Round)
void Route_Transposition_Decryption(char *input, char *output){
	int j=0, k=0; // 2���� �迭�� ���� ����
	int count=0; // 4��° ���� j(��)�� ���������� �ѱ� ����

	// 2���� �迭 [n][4]�� ���� 1��,2��,3��... ������ ���� input�� �ֱ�
	for(int i=0; i<strlen(input); i++, j++,count++){
		j=j%end_j;
		k=count/end_j;
		route_array[j][k]=input[i];
	}

	j=0,k=0,count=0;
	// 2���� �迭���� output�� ���� ���ʴ�� �ֱ�
	for(int i=0; i<strlen(input); i++, k++,count++){	
		k=k%4;
		j=count/4;
		output[i]=route_array[j][k];
	}
}

// ���� ���� ġȯ ��ȣȭ(4Round)
void Multiple_Single_Substitution_Encryption(char *input, char *output, char *key){
	int key_count=0;
	for(int i=0; i<strlen(input); i++, key_count++){
		key_count=key_count%strlen(key);
		if(input[i] >= 'a' && input[i] <= 'z'){
			if(key[key_count] >= 'a' && key[key_count] <= 'z')
				output[i]=vigenere_table_lower[input[i]-97][key[key_count]-97];
			else if(key[key_count] >= 'A' && key[key_count] <= 'Z')
				output[i]=vigenere_table_lower[input[i]-97][key[key_count]-65];
		}
		else if(input[i] >= 'A' && input[i] <= 'Z'){			
			if(key[key_count] >= 'a' && key[key_count] <= 'z')
				output[i]=vigenere_table_upper[input[i]-65][key[key_count]-97];
			else if(key[key_count] >= 'A' && key[key_count] <= 'Z')
				output[i]=vigenere_table_upper[input[i]-65][key[key_count]-65];
		}
		else
			output[i]=input[i];
	}
}

// ���� ���� ġȯ ��ȣȭ(4Round)
void Multiple_Single_Substitution_Decryption(char *input, char *output, char *key){
	int key_count=0;
	for(int i=0; i<strlen(input); i++, key_count++){
		key_count=key_count%strlen(key);
		if(input[i] >= 'a' && input[i] <= 'z'){
			if(key[key_count] >= 'a' && key[key_count] <= 'z'){
				if((input[i]-97)-(key[key_count]-97)<0)
					output[i]=123-abs((input[i]-97)-(key[key_count]-97));
				else
					output[i]=97+(input[i]-97)-(key[key_count]-97);
			}
			else if(key[key_count] >= 'A' && key[key_count] <= 'Z'){
				if((input[i]-97)-(key[key_count]-65)<0)
					output[i]=123-abs((input[i]-97)-(key[key_count]-65));
				else
					output[i]=97+(input[i]-97)-(key[key_count]-65);
			}
		}
		else if(input[i] >= 'A' && input[i] <= 'Z'){
			if(key[i] >= 'a' && key[i] <= 'z'){
				if((input[i]-65)-(key[key_count]-97)<0)
					output[i]=91-abs((input[i]-65)-(key[key_count]-97));
				else
					output[i]=65+(input[i]-65)-(key[key_count]-97);
			}
			else if(key[i] >= 'A' && key[i] <= 'Z'){
				if((input[i]-65)-(key[key_count]-65)<0)
					output[i]=91-abs((input[i]-65)-(key[key_count]-65));
				else
					output[i]=65+(input[i]-65)-(key[key_count]-65);
			}
		}
		else
			output[i]=input[i];
	}
}

// �����׸� �� �ִ� �Լ� (�ҹ���)
void Vigenere_Value_Lower(char input_vigenere[26][26]){
	char start_vigenere = 'a';
		for(int i=0; i<26; i++){
			for(int j=0; j<26; j++)
				input_vigenere[i][j]=(start_vigenere-'a'+j)%26+'a';
			start_vigenere +=1;
		}
}

// �����׸� �� �ִ� �Լ� (�빮��)
void Vigenere_Value_Upper(char input_vigenere[26][26]){
	char start_vigenere = 'A';
		for(int i=0; i<26; i++){
			for(int j=0; j<26; j++)
				input_vigenere[i][j]=(start_vigenere-'A'+j)%26+'A';
			start_vigenere +=1;
		}
}

// �����׸� �� Ȯ��
void Vigenere_Print(char vigenere[26][26]){
	for(int i=0; i<26; i++){
		for(int j=0; j<26; j++)
			printf("%c",vigenere[i][j]);
		printf("\n");
	}
}

// ���ϱ׸� ȸ���� ��ȣȭ, ��ȣȭ(5Round)(Parallel)
void Enigma_Parallel(char *input, char *output, char enigma_before_roter_lower[threads][6][26], char enigma_before_roter_upper[threads][6][26]){
	char enigma_after_lower[threads][6][26];
	char enigma_before_lower[threads][6][26];
	char enigma_after_upper[threads][6][26];
	char enigma_before_upper[threads][6][26];
	int num2_count=0;
	int num3_count=0;
	int rotor_start_num=0;
	int rotor_mid_num=0;
	int rotor_end_num=0;
	int reflector_num=0;

	for(int i=0; i<threads; i++){
		for(int j=0; j<6; j++){
			for(int k=0; k<26; k++){
				enigma_before_lower[i][j][k]=enigma_before_roter_lower[i][j][k];
				enigma_before_upper[i][j][k]=enigma_before_roter_upper[i][j][k];
			}
		}
	}

	int *start = new int[threads];
	int *end = new int[threads];
	for(int i=0; i<threads; i++){
		start[i] = (strlen(input)/threads)*i;
		end[i] = (strlen(input)/threads)*(i+1);

		if(i == threads-1)
			end[i] = strlen(input);
	}

	#pragma omp parallel num_threads(threads) firstprivate(num2_count,num3_count,enigma_before_lower,enigma_after_lower,enigma_before_upper,enigma_after_upper,rotor_start_num,rotor_mid_num,rotor_end_num,reflector_num)
	{
		int tID= omp_get_thread_num();
		
		for(int i=start[tID]; i<end[tID]; i++, num2_count++, num3_count++){
			if(input[i] >= 'a' && input[i] <= 'z'){				
				rotor_start_num=Rotor_Find_Parallel_Start(enigma_before_lower,0,input[i]-97,tID);
				rotor_mid_num=Rotor_Find_Parallel_Start(enigma_before_lower,2,rotor_start_num,tID);
				rotor_end_num=Rotor_Find_Parallel_Start(enigma_before_lower,4,rotor_mid_num,tID);
				
				reflector_num=Reflector_Find(reflector_lower,rotor_end_num);
				
				rotor_start_num=Rotor_Find_Parallel_Turn(enigma_before_lower,5,reflector_num,tID);
				rotor_mid_num=Rotor_Find_Parallel_Turn(enigma_before_lower,3,rotor_start_num,tID);
				rotor_end_num=Rotor_Find_Parallel_Turn(enigma_before_lower,1,rotor_mid_num,tID);
	
				output[i]=rotor_end_num+97;
				//printf("[%d], [%c]\n",tID,rotor_end_num+97);
	
				for(int i=0; i<26; i++){
					enigma_after_lower[tID][0][(i+1)%(26)]=enigma_before_lower[tID][0][i];
					enigma_after_lower[tID][1][(i+1)%(26)]=enigma_before_lower[tID][1][i];
				}
				for(int i=0; i<26; i++){
					enigma_before_lower[tID][0][i]=enigma_after_lower[tID][0][i];
					enigma_before_lower[tID][1][i]=enigma_after_lower[tID][1][i];
				}

				if(num2_count == 26){
					num2_count=0;
					for(int i=0; i<26; i++){
						enigma_after_lower[tID][2][(i+1)%(26)]=enigma_before_lower[tID][2][i];
						enigma_after_lower[tID][3][(i+1)%(26)]=enigma_before_lower[tID][3][i];
					}
					for(int i=0; i<26; i++){
						enigma_before_lower[tID][2][i]=enigma_after_lower[tID][2][i];
						enigma_before_lower[tID][3][i]=enigma_after_lower[tID][3][i];
					}
				}
	
				if(num3_count == 26*26){
					num3_count=0;
					for(int i=0; i<26; i++){
						enigma_after_lower[tID][4][(i+1)%(26)]=enigma_before_lower[tID][4][i];
						enigma_after_lower[tID][5][(i+1)%(26)]=enigma_before_lower[tID][5][i];
					}
					for(int i=0; i<26; i++){
						enigma_before_lower[tID][4][i]=enigma_after_lower[tID][4][i];
						enigma_before_lower[tID][5][i]=enigma_after_lower[tID][5][i];
					}
				}
			}


			else if(input[i] >= 'A' && input[i] <= 'Z'){
				rotor_start_num=Rotor_Find_Parallel_Start(enigma_before_upper,0,input[i]-65,tID);
				rotor_mid_num=Rotor_Find_Parallel_Start(enigma_before_upper,2,rotor_start_num,tID);
				rotor_end_num=Rotor_Find_Parallel_Start(enigma_before_upper,4,rotor_mid_num,tID);
							
				reflector_num=Reflector_Find(reflector_upper,rotor_end_num);
				
				rotor_start_num=Rotor_Find_Parallel_Turn(enigma_before_upper,5,reflector_num,tID);
				rotor_mid_num=Rotor_Find_Parallel_Turn(enigma_before_upper,3,rotor_start_num,tID);
				rotor_end_num=Rotor_Find_Parallel_Turn(enigma_before_upper,1,rotor_mid_num,tID);
	
				output[i]=rotor_end_num+65;
	
				for(int i=0; i<26; i++){
					enigma_after_upper[tID][0][(i+1)%(26)]=enigma_before_upper[tID][0][i];
					enigma_after_upper[tID][1][(i+1)%(26)]=enigma_before_upper[tID][1][i];
				}
				for(int i=0; i<26; i++){
					enigma_before_upper[tID][0][i]=enigma_after_upper[tID][0][i];
					enigma_before_upper[tID][1][i]=enigma_after_upper[tID][1][i];
				}
	
				if(num2_count == 26){
					num2_count=0;
					for(int i=0; i<26; i++){
						enigma_after_upper[tID][2][(i+1)%(26)]=enigma_before_upper[tID][2][i];
						enigma_after_upper[tID][3][(i+1)%(26)]=enigma_before_upper[tID][3][i];
					}
					for(int i=0; i<26; i++){
						enigma_before_upper[tID][2][i]=enigma_after_upper[tID][2][i];
						enigma_before_upper[tID][3][i]=enigma_after_upper[tID][3][i];
					}
				}
	
				if(num3_count == 26*26){
					num3_count=0;
					for(int i=0; i<26; i++){
						enigma_after_upper[tID][4][(i+1)%(26)]=enigma_before_upper[tID][4][i];
						enigma_after_upper[tID][5][(i+1)%(26)]=enigma_before_upper[tID][5][i];
					}
					for(int i=0; i<26; i++){
						enigma_before_upper[tID][4][i]=enigma_after_upper[tID][4][i];
						enigma_before_upper[tID][5][i]=enigma_after_upper[tID][5][i];
					}
				}
			}

			else{
				output[i]=input[i];
			}
		}
	}
}

// Rotor �� ����(��,�ҹ���)
void Rotor_Value(){
	for(int i=0; i<threads; i++){
		for(int j=0; j<6; j++){
			for(int k=0; k<26; k++){
				enigma_rotor_lower_parallel[i][j][k] = enigma_rotor_lower_serial[j][k];
				enigma_rotor_upper_parallel[i][j][k] = enigma_rotor_upper_serial[j][k];
			}
		}
	}
}

// Reflector�� �� �ֱ� (�ҹ���)
void Reflector_Value_Lower(char refl[26]){
	int num=3;
	for(int i=0; i<26; i++){
		refl[i]=((i+num)%13)+97;
		num+=4;
	}
	num+=4;
}

// Reflector�� �� �ֱ� (�빮��)
void Reflector_Value_Upper(char refl[26]){
	int num=3;
	for(int i=0; i<26; i++){
		refl[i]=((i+num)%13)+65;
		num+=4;
	}
	num+=4;
}

// Reflector �� ���
void Reflector_print(char refl[26]){
	for(int i=0; i<26; i++)
		printf("[%2c]",refl[i]);
}

// ȸ���� �� ã�� �Լ� (Reflector ����) (Parallel)
int Rotor_Find_Parallel_Start(char rotor[4][6][26], int rotor_num, int num, int tid){
	for(int i=0; i<26; i++)
		if(rotor[tid][rotor_num][num]==rotor[tid][rotor_num+1][i])
			return i;
}

// ȸ���� �� ã�� �Լ� (���ƿ��� ����) (Parallel)
int Rotor_Find_Parallel_Turn(char rotor[4][6][26], int rotor_num, int num, int tid){
	for(int i=0; i<26; i++)
		if(rotor[tid][rotor_num][num]==rotor[tid][rotor_num-1][i])
			return i;
}

// ���÷��� �� ã�� �Լ�
int Reflector_Find(char refl[26], int num){
	int find_num=0;
	for(int i=0; i<26; i++)
		if(i!=num)
			if(refl[i]==refl[num])
				return i;
}
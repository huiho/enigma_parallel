#include <stdio.h>
#include <omp.h>
#include "DS_timer.h"

#define threads 8
#define FILE_SIZE (1024*1024*32)

void Simple_transposition_Encryption(char *input, char *output, int num); // 단순 전치 암호화(1Round)
void Simple_transposition_Decryption(char *input, char *output, int num); // 단순 전치 복호화(1Round)
void Simple_Substitution_Encryption(char *input, char *output); // 단순 치환 암호화(2Round)
void Simple_Substitution_Decryption(char *input, char *output); // 단순 치환 복호화(2Round)
void Route_Transposition_Encryption(char *input, char *output); // 경로 치환 암호화(3Round)
void Route_Transposition_Decryption(char *input, char *output); // 경로 치환 복호화(3Round)
void Multiple_Single_Substitution_Encryption(char *input, char *output, char *key); // 다중 단일 치환 암호화(4Round)
void Multiple_Single_Substitution_Decryption(char *input, char *output, char *key); // 다중 단일 치환 복호화(4Round)
// 에니그마 회전자 암호화, 복호화(5Round) (parallel)
void Enigma_Parallel(char *input, char *output, char enigma_before_roter_lower[4][6][26], char enigma_before_roter_upper[4][6][26]);

char* plain_text1 = new char[FILE_SIZE]; // 평문
char* plain_text2 = new char[FILE_SIZE]; // 평문을 암호화한 암호문
char* plain_text3 = new char[FILE_SIZE]; // 암호문을 다시 복호화한 평문

char** route_array = new char*[FILE_SIZE];	// 경로 치환에 사용할 2차원 배열
int end_j=0; // 경로 치환에서 마지막 행위치를 저장할 변수

char vigenere_table_lower[26][26]; // 비지네르 배열(소문자)
char vigenere_table_upper[26][26]; // 비지네르 배열(대문자)
void Vigenere_Value_Lower(char input_vigenere[26][26]); // 비지네르 값 넣는 함수(소문자)
void Vigenere_Value_Upper(char input_vigenere[26][26]); // 비지네르 값 넣는 함수(대문자)
void Vigenere_Print(char vigenere[26][26]);	// 비지네르 값 출력 함수
char key[20]; // 다중 단일 치환에 사용할 키

// 회전자 값
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
void Rotor_Value(); // 회전자 값 설정 (대,소문자),(Parallel)

char reflector_lower[26];
char reflector_upper[26];
void Reflector_Value_Lower(char refl[26]); // 리플렉터에 값 넣는 함수(소문자)
void Reflector_Value_Upper(char refl[26]); // 리플렉터에 값 넣는 함수(대문자)
void Reflector_print(char refl[26]);	// 리플렉터 값 출력 함수

int Rotor_Find_Start(char rotor[6][26], int rotor_num, int num); // 회전자 값 찾는 함수(시작하는 방향)
int Rotor_Find_Turn(char rotor[6][26], int rotor_num, int num); // 회전자 값 찾는 함수(돌아오는 방향)
int Rotor_Find_Parallel_Start(char rotor[4][6][26], int rotor_num, int num, int tid);
int Rotor_Find_Parallel_Turn(char rotor[4][6][26], int rotor_num, int num, int tid);
int Reflector_Find(char refl[26], int num); // 리플렉터 값 찾기 함수

void Version1();

void main(){

	FILE *input = fopen("input.txt","r");
	FILE *ciphertext = fopen("ciphertext.txt","w");
	FILE *output = fopen("output.txt","w");

	DS_timer timer(4);
	timer.initTimers();

	/*
	// 경로 치환에서 사용할 배열 할당
	for(int i = 0; i<FILE_SIZE; i++)
		route_array[i] = new char[4];
	*/

	/*
	// 비지네르 값 넣기
	Vigenere_Value_Lower(vigenere_table_lower);
	Vigenere_Value_Upper(vigenere_table_upper);
	// 비지네르 확인
	Vigenere_Print(vigenere_table_lower);
	printf("키를 입력하세요: ");
	scanf("%s",key);	 // 다중 치환에서 사용할 키
	*/

	for(int i=0; i<26; i++)
		printf("[%2c]",'a'+i);
	printf("\n\n");

	// Roter 값 설정
	Rotor_Value();

	// Reflector 값 설정 및 출력
	Reflector_Value_Lower(reflector_lower);
	Reflector_Value_Upper(reflector_upper);
	Reflector_print(reflector_lower);

	/*
	// 키보드로 입력받기
	printf("\n\n암호화할 평문을 입력하세요.\n\n");	
	fgets(plain_text1, sizeof(plain_text1),stdin); // 모든 문자열 다 받음(문자, 숫자, 띄어쓰기, 개행문자(enter))
	plain_text1[strlen(plain_text1)-1]=NULL;	 // 개행문자 NULL만들기
	*/
	
	// Version 1
	// 파일로 입력받기
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

// 단순 전치 암호화(1Round)
void Simple_transposition_Encryption(char *input, char *output, int num) {
	for(int i=0; i<strlen(input); i++)
		output[ (i+num) % (strlen(input)) ] = input[i];
}

// 단순 전치 복호화(1Round)
void Simple_transposition_Decryption(char *input, char *output, int num) {
	for(int i=0; i<strlen(input); i++)
		output[ (i+strlen(input)-num) % (strlen(input)) ] = input[i];
}

// 단순 치환 암호화(2Round)
void Simple_Substitution_Encryption(char *input, char *output){
	// 3 대신 어떤 수식을 만들어서 대입해도 가능(예 3 x + 5 (mod 26))
	for(int i=0; i<strlen(input); i++)
		output[i] = input[i] + 3;
}

// 단순 치환 복호화(2Round)
void Simple_Substitution_Decryption(char *input, char *output){
	// 3 대신 어떤 수식을 만들어서 대입해도 가능(예 3 x + 5 (mod 26))
	for(int i=0; i<strlen(input); i++)
		output[i] = input[i] - 3;
}

// 경로 치환 암호화(3Round)
void Route_Transposition_Encryption(char *input, char *output){
	int j=0, k=0; // 2차원 배열에 넣을 변수

	int count=0; // 4번째 마다 j(행)을 다음행으로 넘길 변수

	// input에서 2차원 배열에 [n][4]에 값을 차례대로 넣기
	for(int i=0; i<strlen(input); i++, k++, count++){
		k=k%4;
		j=count/4;
		route_array[j][k]=input[i];
	}
	end_j=j+1;
	j=0, k=0, count=0;

	// 2차원 배열 [n][4]에 값을 1행,2행,3행... 순으로 값을 ouput에 넣기
	for(int i=0; i<strlen(input); i++, j++,count++){
		j=j%end_j;
		k=count/end_j;
		output[i]=route_array[j][k];
	}
}

// 경로 치환 복호화(3Round)
void Route_Transposition_Decryption(char *input, char *output){
	int j=0, k=0; // 2차원 배열에 넣을 변수
	int count=0; // 4번째 마다 j(행)을 다음행으로 넘길 변수

	// 2차원 배열 [n][4]에 값을 1행,2행,3행... 순으로 값을 input에 넣기
	for(int i=0; i<strlen(input); i++, j++,count++){
		j=j%end_j;
		k=count/end_j;
		route_array[j][k]=input[i];
	}

	j=0,k=0,count=0;
	// 2차원 배열에서 output에 값을 차례대로 넣기
	for(int i=0; i<strlen(input); i++, k++,count++){	
		k=k%4;
		j=count/4;
		output[i]=route_array[j][k];
	}
}

// 다중 단일 치환 암호화(4Round)
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

// 다중 단일 치환 복호화(4Round)
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

// 비지네르 값 넣는 함수 (소문자)
void Vigenere_Value_Lower(char input_vigenere[26][26]){
	char start_vigenere = 'a';
		for(int i=0; i<26; i++){
			for(int j=0; j<26; j++)
				input_vigenere[i][j]=(start_vigenere-'a'+j)%26+'a';
			start_vigenere +=1;
		}
}

// 비지네르 값 넣는 함수 (대문자)
void Vigenere_Value_Upper(char input_vigenere[26][26]){
	char start_vigenere = 'A';
		for(int i=0; i<26; i++){
			for(int j=0; j<26; j++)
				input_vigenere[i][j]=(start_vigenere-'A'+j)%26+'A';
			start_vigenere +=1;
		}
}

// 비지네르 값 확인
void Vigenere_Print(char vigenere[26][26]){
	for(int i=0; i<26; i++){
		for(int j=0; j<26; j++)
			printf("%c",vigenere[i][j]);
		printf("\n");
	}
}

// 에니그마 회전자 암호화, 복호화(5Round)(Parallel)
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

// Rotor 값 설정(대,소문자)
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

// Reflector에 값 넣기 (소문자)
void Reflector_Value_Lower(char refl[26]){
	int num=3;
	for(int i=0; i<26; i++){
		refl[i]=((i+num)%13)+97;
		num+=4;
	}
	num+=4;
}

// Reflector에 값 넣기 (대문자)
void Reflector_Value_Upper(char refl[26]){
	int num=3;
	for(int i=0; i<26; i++){
		refl[i]=((i+num)%13)+65;
		num+=4;
	}
	num+=4;
}

// Reflector 값 출력
void Reflector_print(char refl[26]){
	for(int i=0; i<26; i++)
		printf("[%2c]",refl[i]);
}

// 회전자 값 찾기 함수 (Reflector 방향) (Parallel)
int Rotor_Find_Parallel_Start(char rotor[4][6][26], int rotor_num, int num, int tid){
	for(int i=0; i<26; i++)
		if(rotor[tid][rotor_num][num]==rotor[tid][rotor_num+1][i])
			return i;
}

// 회전자 값 찾기 함수 (돌아오는 방향) (Parallel)
int Rotor_Find_Parallel_Turn(char rotor[4][6][26], int rotor_num, int num, int tid){
	for(int i=0; i<26; i++)
		if(rotor[tid][rotor_num][num]==rotor[tid][rotor_num-1][i])
			return i;
}

// 리플렉터 값 찾기 함수
int Reflector_Find(char refl[26], int num){
	int find_num=0;
	for(int i=0; i<26; i++)
		if(i!=num)
			if(refl[i]==refl[num])
				return i;
}
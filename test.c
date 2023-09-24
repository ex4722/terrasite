#include <stdio.h>

void test_1();
void test_2();

int main(){
    int counter = 0;
    printf("IN MAIN\n");
    for(int i =0; i < 10; i++){
        counter++;
    }
    printf("COUNTER IS %d\n",counter);
    test_1();
    test_2();
}

void test_1(){
    printf("THIS IS TEST1\n");
}

void test_2(){
    printf("THIS IS TEST2\n");
}

/*
DONATE TeleminerstD
BTC - 1F7tctXBtjnSJEMwPEQc4P4GZGDqEZHVP1
ZEC - t1XwmdEZkKKwtQVgF2jvxBTAWheYDVLrUMX
Thanks )))
*/

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <netdb.h>
#include <time.h>
#include <sys/wait.h>
#include <fcntl.h> 
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h> 

#define BREADSIZE 2048

int fd;
int counter = 0;
int count_error = 0;
int port = 0;
char token[64] = {0,};
char glob_chat_id[16] = {0,};
char res_pminer[512] = {0,};
char stor_buff[2048] = {0,};
char vkl_data = 'Z';

char data_on[16] = {0,};
char data_off[16] = {0,};
char all_off[16] = {0,};

int count_dat = 0;
char reb_komp[16] = {0,};
char off_komp[16] = {0,};

/////////////////////////////////////////////////// error_log ///////////////////////////////////////////////////////
void error_log(char *my_error) 
{ 
   time_t t;
   time(&t);
   FILE *f;
   struct stat st;	
   stat("Errteleminerstd.log",&st);
	
   if(st.st_size < 4096) f = fopen("Errteleminerstd.log", "a"); 
   else f = fopen("Errteleminerstd.log", "w");
   if(f == NULL)
    {
      printf("Error open Errteleminerstd.log.\n");
      exit(0);
    }

   fprintf(f, "%s", ctime( &t));
   fprintf(f, "Error: %s\n\n", my_error);
   printf("Error: %s Write to Errteleminerstd.log.\n", my_error);
   fclose(f);
   if(my_error[strlen(my_error) - 1] == '!') exit(0);
}

/////////////////////////////////////////////////// read_conf ///////////////////////////////////////////////////////
void read_conf()
{  
   FILE *mf;
   char *restr;
   mf = fopen ("teleminerstd.conf","r");
   if(mf == NULL) error_log("config-file!");
   printf ("Open config file.\n");
   while(1)
    { 
      char str[512] = {0,};
      restr = fgets(str, 510, mf);
      if(restr == NULL)
       {
         if(feof(mf) != 0) break; 
         else error_log("read from config file!");
       }

      if(strstr(str,"port=") != NULL) { port = atoi(strstr(str, "port=") + 5); printf("Port=%d\n", port); }

      else if((restr = strstr(str, "token=")) != NULL) 
       {
         int index = (restr - str) + 6;
         int i = 0;
         for(; i <= 62; i++)
          {
            token[i] = str[index];
            index++;
            if(token[i] == '\n') 
             {
               token[i] = '\0';
               printf("Token=%s\n", token);
               break;
             }
          }
       }
     
      else if((restr = strstr(str, "pminer=")) != NULL) 
       {
         char pminer[512] = {0,};
         int index = (restr - str) + 7;
         int i = 0;
         for(; i <= 510; i++)
          {
            pminer[i] = str[index];
            index++;
            if(pminer[i] == '\n') 
             {
               pminer[i] = '\0';
               snprintf(res_pminer, 29 + strlen(pminer), "LD_PRELOAD=./line_buffer.so %s", pminer);
               printf("Pminer=%s\n", pminer);
               break;
             }
          }
       }

      else if((restr = strstr(str, "globchatid=")) != NULL) 
       {
         int index = (restr - str) + 11;
         int i = 0;
         for(; i <= 14; i++)
          {
            glob_chat_id[i] = str[index];
            index++;
            if(glob_chat_id[i] == '\n') 
             {
               glob_chat_id[i] = 0;
               printf("Globchatid=%s\n", glob_chat_id);
               break;
             }
          }
       }


      else if((restr = strstr(str, "data_on=")) != NULL) 
       {
         int index = (restr - str) + 8;
         int i = 0;
         for(; i <= 14; i++)
          {
            data_on[i] = str[index];
            index++;
            if(data_on[i] == '\n') 
             {
               data_on[i] = 0;
               printf("Data_on=%s\n", data_on);
               break;
             }
          }
       }

      else if((restr = strstr(str, "data_off=")) != NULL) 
       {
         int index = (restr - str) + 9;
         int i = 0;
         for(; i <= 14; i++)
          {
            data_off[i] = str[index];
            index++;
            if(data_off[i] == '\n') 
             {
               data_off[i] = 0;
               printf("Data_off=%s\n", data_off);
               break;
             }
          }
       }
       
      else if((restr = strstr(str, "all_off=")) != NULL) 
       {
         int index = (restr - str) + 8;
         int i = 0;
         for(; i <= 14; i++)
          {
            all_off[i] = str[index];
            index++;
            if(all_off[i] == '\n') 
             {
               all_off[i] = 0;
               printf("All_off=%s\n", all_off);
               break;
             }
          }
       }       
       
      else if(strstr(str,"count_dat=") != NULL) { count_dat = atoi(strstr(str, "count_dat=") + 10); printf("Count_dat=%d\n", count_dat); }

      else if((restr = strstr(str, "reb_komp=")) != NULL) 
       {
         int index = (restr - str) + 9;
         int i = 0;
         for(; i <= 14; i++)
          {
            reb_komp[i] = str[index];
            index++;
            if(reb_komp[i] == '\n') 
             {
               reb_komp[i] = 0;
               printf("Reb_komp=%s\n", reb_komp);
               break;
             }
          }
       }
       
      else if((restr = strstr(str, "off_komp=")) != NULL) 
       {
         int index = (restr - str) + 9;
         int i = 0;
         for(; i <= 14; i++)
          {
            off_komp[i] = str[index];
            index++;
            if(off_komp[i] == '\n') 
             {
               off_komp[i] = 0;
               printf("Off_komp=%s\n", off_komp);
               break;
             }
          }
       }       

    } // END while

   if(fclose(mf) == EOF) error_log("mf EOF!");
   printf ("Close config file.\n");

} // END read_conf

/////////////////////////////////////////////////// child_kill ///////////////////////////////////////////////////////
void child_kill() 
{  
   wait(NULL); 
} 

void child_kill2() 
{ 
   wait(NULL); 
} 

/////////////////////////////////////////////////// time count ///////////////////////////////////////////////////////
void * timecount_func() 
 {  
   for(;;)
    { 
      if(count_error == 10)
       { 
        counter++;
        printf("Timer=%dsec\n", counter);
        if(counter > 599)
         {
		   counter = 0;
		   count_error = 9; 
		 }	 
       } 
       
      sleep(1); 
    }
   return 0;
 } 

/////////////////////////////////////////////////// SendMessage ///////////////////////////////////////////////////////
void SendMessage(char *chat_id, char *send_text) 
{
	pid_t smpid;  
    signal(SIGCHLD, child_kill2);  
    smpid = fork();
	if(smpid == 0) 
     { 
       char str[1024] = {0,};
       int lenstr = 95; 
       char json_str[256] = {0,};
       snprintf(json_str, 1 + 11 + (int)strlen(chat_id) + 9 + (int)strlen(send_text) + 2, "%s%s%s%s%s", "{\"chat_id\":", chat_id, ",\"text\":\"", send_text, "\"}");
   
       int lenjson = (int)strlen(json_str);
       snprintf(str, 1 + 9 + (int)strlen(token) + lenstr + 3 + 23 + lenjson, "%s%s%s%d%s%s", "POST /bot", token, "/sendMessage HTTP/1.1\r\nHost: api.telegram.org\r\nContent-Type: application/json\r\nContent-Length: ", lenjson, "\r\nConnection: close\r\n\r\n", json_str);

       //////////////////////////////////// client ///////////////////////////////////////////
       struct sockaddr_in serv_addr;
       int sd = 0;

       sd = socket(AF_INET, SOCK_STREAM, 0);
       if (sd < 0) error_log("socket in SM!");
       
       struct timeval timeout;      
       timeout.tv_sec = 5;
       timeout.tv_usec = 0;
       if(setsockopt (sd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) error_log("setsockopt.");
      
       memset(&serv_addr, 0, sizeof(serv_addr));
       serv_addr.sin_family = AF_INET;
       serv_addr.sin_addr.s_addr = inet_addr("149.154.167.198");
       serv_addr.sin_port = htons(443);

       if(connect(sd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
        {
	      error_log("connect.");
	      if(close(sd) == -1) error_log("close sd in SendMessage!");
          exit(0);
	    }
	
       /////////////////////////////////// ssl client ////////////////////////////////////////
       SSL_CTX * sslctx = SSL_CTX_new(TLSv1_2_client_method());
       SSL * cSSL = SSL_new(sslctx);
       if(SSL_set_fd(cSSL, sd) == 0) error_log("SSL_set_fd in SM!");
       if(SSL_connect(cSSL) == 0) error_log("SSL_connect in SM!"); 

       /////////////////////////////////// send mesg ////////////////////////////////////////
       int vsm = SSL_write(cSSL, str, (int)strlen(str));
       if(vsm <= 0)
        {
          SSL_free(cSSL);
          if(close(sd) == -1) error_log("close sd in SM!");
          error_log("vsm = SSL_write in SM!");            
        }

       memset(str, 0, 1024);
   
       /////////////////////////////////// read response ////////////////////////////////////
       int n = SSL_read(cSSL, str, 1022); 
       if(n <= 0)
        {
          SSL_free(cSSL);
          if(close(sd) == -1) error_log("close client_3!");
          error_log("Err SSL_read in SM.");
        } 

       /////////////////////////////////// close connect ////////////////////////////////////
       SSL_free(cSSL);
       SSL_CTX_free(sslctx);
       if(close(sd) == -1) error_log("close sd in SendMessage!");
       exit(0);
       
     } // END FORK

} // END SendMessage

////////////////////////////////////////////////// miner_thread_func ///////////////////////////////////////////////////////
void * miner_thread_func() 
 { 
	FILE *prog_miner;
	char buff[256] = {0,};
    char res_buff[256] = {0,};
    int count = 0;
    
    prog_miner = popen(res_pminer, "r");
	if(prog_miner == NULL) error_log("popen miner!");

    printf("START MINER and WAIT DATA.\n\n");
 
	while(fgets(buff, 254, prog_miner) != NULL)
     {
       printf("DATA: %s", buff);
       int buff_len = (int)strlen(buff);
       int indexin = 0;
       int indexout = 0;
       while(indexin < buff_len)
        { 
          if(buff[indexin] == '\x1b') 
           {
             for(; indexin < buff_len; indexin++)
              { 
                if(buff[indexin] == 'm')
                 { 
                   buff[indexin] = ' ';
                   break;
                 }          
              }
           }

          res_buff[indexout] = buff[indexin];

          if(res_buff[indexout] == '\n') 
           {
             res_buff[indexout] = 0;
             

             if(vkl_data == 'A') 
              { 
                SendMessage(glob_chat_id, res_buff);
                count++;
                if(count >= count_dat)
                 {
                   count = 0;
                   vkl_data = 'Z';
                   SendMessage(glob_chat_id, "DATA OFF");
                 } 
              }
              
             else if(vkl_data == 'Z') 
              {
                count = 0;

                if(count_error < 10 && (strstr(res_buff, "ERROR") != NULL || strstr(res_buff, "Host not found") != NULL || strstr(res_buff, "Worker not authorized") != NULL || strstr(res_buff, "WARNING") != NULL))
                 {
				   if(count_error == 0) 
				    {
				      SendMessage(glob_chat_id, "START MSG ERROR");
				      sleep(1);
			        }
			        
                   printf("Send error:%d %s\n", count_error, res_buff);
                   SendMessage(glob_chat_id, res_buff); 
                   
                   if(count_error == 9) 
                    {
					  sleep(1);	
                      SendMessage(glob_chat_id, "STOP MSG ERROR");
			        }
                   count_error++;
                 }
              }  

             break;
           }

          indexin++;
          indexout++;

         }

        memset(buff, 0, 256);
        memset(res_buff, 0, 256);
	 }

	if(pclose(prog_miner) == -1) error_log("pclose!");
    return 0;

 } // END miner_thread

//////////////////////////////////////////// MAIN ///////////////////////////////////////////
int main() 
{
    printf("\nDONATE TeleminerstD\n");
	printf("BTC - 1F7tctXBtjnSJEMwPEQc4P4GZGDqEZHVP1\n");
	printf("ZEC - t1XwmdEZkKKwtQVgF2jvxBTAWheYDVLrUMX\n");
    printf("Thanks )))\n\n");
	sleep(2);
	
    read_conf();

    //////////////////////////////////    miner_thread    ////////////////////////////////////
    pthread_t miner_thread;
    int min_result = pthread_create(&miner_thread, NULL, &miner_thread_func, NULL); 
    if(min_result != 0) error_log("creating miner_thread!");
    pthread_detach(miner_thread);
    
    //////////////////////////////    ttimecount_func     ////////////////////////////////////
    pthread_t counterr_thread;
    int result2 = pthread_create(&counterr_thread, NULL, &timecount_func, NULL); 
    if(result2 != 0) error_log("creating timecount_func!");
    pthread_detach(counterr_thread);    

    ////////////////////////////////////    ssl    //////////////////////////////////////////
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    SSL_CTX * sslctx = SSL_CTX_new(TLSv1_2_server_method());

    /////////////////////////////    read certificate    ////////////////////////////////////
    if(SSL_CTX_use_certificate_file(sslctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) error_log("use_certificate_file!");
    if(SSL_CTX_use_PrivateKey_file(sslctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) error_log("use_PrivateKey_file!");
    if(!SSL_CTX_check_private_key(sslctx)) error_log("check_private_key!");

    ///////////////////////////////////    server    ////////////////////////////////////////
    int sd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sd < 0) error_log("descriptor socket!");
    int one = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
 
    struct sockaddr_in s_addr;
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(port);

    if(bind(sd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) error_log("binding!");

    if(listen(sd, 5) == -1) 
     {
       close(sd);
       error_log("listen!");
     }

    char read_buffer[BREADSIZE] = {0,};
    int client = 0;
    
    SendMessage(glob_chat_id, "START SYSTEM");
  
    while(1) 
     {  
        printf("WAIT CONNECTION.\n\n");
        memset(read_buffer, 0, BREADSIZE);

        client = accept(sd, NULL, NULL); 

        if(client == -1) 
         {
           error_log("Not cl accept.");
           if(close(client) == -1) error_log("close client_1!");
           continue;
         }

        ///////////////////////////// ssl socket //////////////////////////////
        SSL *ssl = SSL_new(sslctx);
        if(SSL_set_fd(ssl, client) == 0) error_log("SSL_set_fd!");

        int acc = SSL_accept(ssl); 
        if(acc <= 0)
         { 
            SSL_free(ssl);
            if(close(client) == -1) error_log("close client_2!");
            error_log("Not SSL_accept.");
            continue;
         }

        /////////////////////////////// pipe /////////////////////////////////// 
        int pip_fd[2];
        int size; 
        if(pipe(pip_fd) < 0) error_log("create pipe!");

        /////////////////////////////// fork ///////////////////////////////////
        pid_t fpid;  
        signal(SIGCHLD, child_kill);  
        fpid = fork();

        //////////////////////// parent read pipe ////////////////////////////// 
        if(fpid > 0) 
         { 
            if(close(pip_fd[1]) < 0) error_log("close parent pip_fd[1]!");
            size = read(pip_fd[0], glob_chat_id, 14);
            if(size < 0) error_log("read chat_id from child!");
            if(close(pip_fd[0]) < 0) error_log("close parent pip_fd[0]!");

            if(glob_chat_id[strlen(glob_chat_id) - 1] == 'A')
             {
			   counter = 0;	 
			   count_error = 0;
               vkl_data = glob_chat_id[strlen(glob_chat_id) - 1];
               glob_chat_id[strlen(glob_chat_id) - 1] = 0;
             }
        
            else if(glob_chat_id[strlen(glob_chat_id) - 1] == 'Z')
             {
               vkl_data = glob_chat_id[strlen(glob_chat_id) - 1];
               glob_chat_id[strlen(glob_chat_id) - 1] = 0;
             }
        
            else if(glob_chat_id[strlen(glob_chat_id) - 1] == 'S')
             {
               vkl_data = glob_chat_id[strlen(glob_chat_id) - 1];
               glob_chat_id[strlen(glob_chat_id) - 1] = 0;
             }     
         }
    
        /////////////////////////// start child ////////////////////////////////
        if(fpid != 0) 
         { 
            SSL_free(ssl);
            if(close(client) == -1) error_log("close client_pid!");
            continue;
         }

        ////////////////////// read header from telegram ///////////////////////
        int n = SSL_read(ssl, read_buffer, BREADSIZE - 2); // first SSL_read
        if(n <= 0)
         {
            SSL_free(ssl);
            if(close(client) == -1) error_log("close client_3!");
            printf("Disconnection:%d\n", n);
            exit(0);           
         } 

        /////////////////////// verification token ////////////////////////////
        if(strstr(read_buffer, token) == NULL) 
         { 
            SSL_free(ssl);
            if(close(client) == -1) error_log("close client_4!");
            error_log("Not valid POST!");
         }

        /////////////////////// chek content-type ////////////////////////////
        if(strstr(read_buffer, "Content-Type: application/json") == NULL) 
         {
            SSL_free(ssl);
            if(close(client) == -1) error_log("close client_5!");
            error_log("Not json!");
         }

        /////////////////////////// read jons data ///////////////////////////// 
        memset(read_buffer, 0, BREADSIZE); 
        int m = SSL_read(ssl, read_buffer, BREADSIZE - 2);  
        if(m <= 0)
         {
            SSL_free(ssl);
            if(close(client) == -1) error_log("close client_8!");
         }

        /////////////////////////// read chat_id ///////////////////////////////
        char *p;
        char chat_id[16] = {0,};
        if((p = strstr(read_buffer, "chat\":{\"id\":")) != NULL) 
         {
           int index = (p - read_buffer) + 12;
           int i = 0;
           for(; i <= 14; i++)
            {
              chat_id[i] = read_buffer[index];
              index++;
              if(chat_id[i] == ',') 
               {
                 chat_id[i] = 0;
                 printf("Chat_id:%s\n", chat_id); 
                 break;
               }
            }
         }

        //////////////////////////// read msag  ////////////////////////////////
        char *q;
        char msg_text[64] = {0,};
        if((q = strstr(read_buffer, "text\":\"")) != NULL) 
         {
           int index = (q - read_buffer) + 7;
           int i = 0;
           for(; i <= 62; i++)
            {
              msg_text[i] = read_buffer[index];
              index++;
              if(msg_text[i] == '"') 
               {
                 msg_text[i] = 0; 
                 printf("Msg_text:%s\n", msg_text);
                 break;
               }
            }
         }

        //////////////////////////// telegram reply  //////////////////////////////
        int v = SSL_write(ssl, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", 38);
        if(v <= 0)
         {
           SSL_free(ssl);
           if(close(client) == -1) error_log("v = SSL_write!");
         }

        SSL_free(ssl);
        if(close(client) == -1) error_log("close client_6!");

        ///////////////////////////// my functions  ////////////////////////////////
        if(msg_text[0] == 't' && msg_text[1] == 0)
         { 
           SendMessage(chat_id, "TEST"); 
         }
      
        else if(strstr(read_buffer, data_on) != NULL)
         {
           vkl_data = 'A';
           SendMessage(chat_id, "DATA ON");
           chat_id[strlen(chat_id)] = vkl_data;
         }

        else if(strstr(read_buffer, data_off) != NULL)
         {
           vkl_data = 'Z';
           SendMessage(chat_id, "DATA OFF");
           chat_id[strlen(chat_id)] = vkl_data;
         }
         
        else if(strstr(read_buffer, all_off) != NULL)
         {
           vkl_data = 'S';
           SendMessage(chat_id, "ALL OFF");
           chat_id[strlen(chat_id)] = vkl_data;
         }         
         
        else if(strstr(read_buffer, reb_komp) != NULL)
         {
           error_log("Not error, received command REBOOT.");			 
           SendMessage(chat_id, "REBOOT");
           system("reboot");
         } 
         
        else if(strstr(read_buffer, off_komp) != NULL)
         {	
           error_log("Not error, received command SHUTDOWN.");		 
           SendMessage(chat_id, "SHUTDOWN");
           system("shutdown -h now");
         }          
  
        if(close(pip_fd[0]) < 0) error_log("close child pip_fd[0]!");
        size = write(pip_fd[1], chat_id, (int)strlen(chat_id));
        if(size != (int)strlen(chat_id)) error_log("write chat_id!");
        if(close(pip_fd[1]) < 0) error_log("close child pip_fd[1]!");

        exit(0); 
  
    } // END while(1) 
 
   if(close(sd) == -1) error_log("close sd client_7!");
}


// gcc -Wall -Wextra teleminerstd.c -o teleminerstd -lcrypto -lssl -pthread

// ./teleminerstd















// make package/teleminerpipe/compile V=s

// "617455910"

/*#include <stdio.h>
#include <locale.h>

int main()
{
  setlocale(LC_ALL, "rus");

  printf("%s", "Привет, мир!");

  return 0;
}*/


	/*char *question[3] = {"Дефляция", "two dva dva", "tri tri tri tri"};
	unsigned int i = 0;
	for(; i < sizeof(question) / sizeof(question[0]); i++) 
	 {
       printf("%d == %s\n", i , question[i]);
     }

	
	printf("\nDONATE TeleminerstD\n\n");
	printf("BTC - 1F7tctXBtjnSJEMwPEQc4P4GZGDqEZHVP1\n\n");
	printf("ZEC - t1XwmdEZkKKwtQVgF2jvxBTAWheYDVLrUMX\n\n");
	printf("THANKS )))\n\n");
	sleep(3);*/


//setlocale(LC_ALL, "Russian");


/*if(strstr(res_buff, "ERROR") != NULL || strstr(res_buff, "Host not found") != NULL || strstr(res_buff, "Worker not authorized") != NULL || strstr(res_buff, "WARNING") != NULL) 
                 {
                   if(count_error == 0)
                    {
                      printf("ERROR_START: %s\n", res_buff);
                      SendMessage(glob_chat_id, res_buff);
                    }

                   if(count_error > 10)
                    {
                      count_error = 0;
                      printf("ERROR: %s\n", res_buff);
                      SendMessage(glob_chat_id, res_buff);
                    }
     
                   count_error++;
                 } */











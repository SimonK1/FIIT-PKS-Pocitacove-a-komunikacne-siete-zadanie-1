
//
//  main.c
//  pokus
//
//  Created by Jozef Varga on 26.9.17.
//  Copyright © 2017 Jozef Varga. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#define DLZKA_MAC_ADD 6
#define DLZKA_IP_ADD 4
#define DLZKA_TCP_HLAVICKY 20

struct ethernet_hlavicka {                      // struktura ktora nam vytvara ethernetovu hlavicku
    u_char ethernet_cielova[DLZKA_MAC_ADD];     // Cielova adresa housta
    u_char ethernet_zdrojova[DLZKA_MAC_ADD];    // Zdrojova adresa housta
    u_short ethernet_typ;                       // typ ethernetu -IP,ARP
};

struct ieee_hlavicka{                           // struct ktora sa vytvara ak to nie je ethernet
    u_char ieee_dsap;
    u_char ieee_skok[5];
    u_short ieee_ethernet_typ;
};

struct ip_hlavicka {                            // struktura ktora nam vytvara ip hlavicku
    u_char ip_verzia;           // verzia IP
    u_char ip_tos;              // type of service
    u_short ip_dlzka;           // celkova dlzka
    u_short ip_id;              // identification
    u_short ip_offset;          // fragment offset field
    u_char ip_ttl;              // time to live
    u_char ip_protokol;         // protokol
    u_short ip_checksum;        // kontrola
    u_char ip_zdrojova[DLZKA_IP_ADD]; // zdrojova IP adresa
    u_char ip_cielova[DLZKA_IP_ADD];  // cielova IP adresa
};

struct tcp_hlavicka {                   // struktura ktora nam vytvara tcp hlavicku
    u_short tcp_zdrojovy_port;          // zdrojovy port
    u_short tcp_cielovy_port;           // cielovy port
    u_int32_t tcp_sequence;             // sequence number
    u_int32_t tcp_acknowledgement;      // acknowledgement number
    u_char tcp_offset;                  // data offset, reserved
    u_char tcp_flags;                   // flag
    u_short tcp_window;                 // window
    u_short tcp_checksum;               // kontrola
    u_short tcp_urgent_pointer;         // urgent pointer
};

struct udp_hlavicka {                   // struktura ktora nam vytvara tcp hlavicku
    u_short  udp_zdrojovy_port;
    u_short  udp_cielovy_port;
    u_short  udp_dlzka;
    u_short  udp_checksum;
};

struct arp_hlavicka{                    // struktura ktora nam vytvara arp hlavicku
    u_short arp_hw_address;
    u_short arp_protocol_address;
    u_char arp_hw_addr_len;
    u_char arp_protocol_address_len;
    u_short arp_operation;
    u_char arp_zdrojova_hw_address[DLZKA_MAC_ADD];
    u_char arp_zdrojova_protocol_address[DLZKA_IP_ADD];
    u_char arp_target_hw_address[DLZKA_MAC_ADD];
    u_char arp_target_protocol_address[DLZKA_IP_ADD];
};

struct icmp_hlavicka{                   // struktura ktora nam vytvara
    u_char icmp_type;
    u_char icmp_code;
};

u_short vymena_bytov(u_short x){
    return x = (x >> 8) | ((x & 255) << 8);
}

int meno_protokolu(FILE *subor,char znak,u_short ethernet_typ_cislo, int x){
    int l=0;
    rewind(subor);  // subor sa cita od zaciatku
    char c;
    while((c=getc(subor))!= EOF){ //citame az do konca suboru
        if(c==znak){ // znak | nak ukazuje v subore ze nasledujuca hodnota patry ethernetovej hlavicke ci je to ARP alebo IP
            fscanf(subor,"%d",&l);  // nacitanie cisla zo suboru a nasledne ho porovname s cislom z framu
            if(ethernet_typ_cislo==l){ // ak sedi tak vypiseme nazov ktory je priradeny ku cislu (je hned za)
                if(x==1){
                    printf("\n");
                    while((c=getc(subor))!= '\n')printf("%c",c);
                }
                break;
            }
        }
    }
    return ethernet_typ_cislo;
}

void meno_portu(FILE *subor, u_short port_zdroj, u_short port_ciel, char x){
    int l=0;
    char c;
    while((c=getc(subor))!= EOF){ // funguje ako hladanie typu (ARP alebo IP) s tym ze teraz hladame ip protokol
        if(c==x){ // znak / nam ukazuje ze dalsia hodnota je priradena ku udp portu
            fscanf(subor,"%d",&l);
            if(port_zdroj==l){
                printf("\n");
                while((c=getc(subor))!= '\n')printf("%c",c);
                break;
            }
            else if(port_ciel==l){
                printf("\n");
                while((c=getc(subor))!= '\n')printf("%c",c);
                break;
            }
        }
    }
}

void vypis_mac_addresy(struct ethernet_hlavicka *ethernet){
    int i;
    printf("\nZdrojova MAC adresa: ");
    for(i=0;i<DLZKA_MAC_ADD;i++)printf("%.2X ",ethernet->ethernet_zdrojova[i]);
    printf("\nCielova MAC adresa: ");
    for(i=0;i<DLZKA_MAC_ADD;i++)printf("%.2X ",ethernet->ethernet_cielova[i]);
}

void hexa_vypis(int i,const u_char *packet){
    int presun_medzi_bytmi;
    for (presun_medzi_bytmi=0; (presun_medzi_bytmi < i ) ; presun_medzi_bytmi++){
        if((presun_medzi_bytmi % 8) == 0 && (presun_medzi_bytmi % 16) != 0)printf(" "); //aby po kazdych 8 bytoch bola medzera
        if ( (presun_medzi_bytmi % 16) == 0) printf("\n"); //aby po kazdych 16 bol novy riadok
        printf("%.2x ", packet[presun_medzi_bytmi]);
    }
    printf("\n\n");
}

void vypis_zaklad(int cislo_ramca, int i,int x){
    printf("Ramec %i\n", cislo_ramca);        //vypis cisla ramca
    printf("Dlzka ramca poskytnuta pcap API %d B\n", i);   //vypis pcap API velkosti ramca
    x=x+4;
    if(x<64)x=64;
    printf("Dlzka ramca prenasaneho po mediu %d B",x);    //vypis velkosti ramca po mediu
}

int velkost_bytov(int x){
    x=x+4;
    if(x<64)x=64;
    return x;
}

void vypis_ip(struct ip_hlavicka *ip){
    printf("\nCielova IP adresa: %d.%d.%d.%d\n",  ip->ip_cielova[0],  ip->ip_cielova[1],  ip->ip_cielova[2],  ip->ip_cielova[3]);
    //vypis zdrojovej IP adresy
    printf("Zdrojova IP adresa: %d.%d.%d.%d",  ip->ip_zdrojova[0],  ip->ip_zdrojova[1],  ip->ip_zdrojova[2],  ip->ip_zdrojova[3]);
}

void vypis_udp_protocol(struct udp_hlavicka *udp){
    printf("\nZdrojovy port: %d",udp->udp_zdrojovy_port);
    printf("\nCielovy port: %d",udp->udp_cielovy_port);
}

void vypis_tcp_protocol(struct tcp_hlavicka *tcp){
    printf("\nZdrojovy port: %d",tcp->tcp_zdrojovy_port);
    printf("\nCielovy port: %d",tcp->tcp_cielovy_port);
}

int vyber_standart(struct ethernet_hlavicka *ethernet, struct ieee_hlavicka *ieee, FILE *subor,int hodnota_zo_suboru,int *dlzka_ethernetovej_hlavicky, const u_char *packet, int ci_sa_vypise){
    int vyber_protokolu;
    if(ethernet->ethernet_typ > 1500){
        hodnota_zo_suboru=meno_protokolu(subor,'#', ((ethernet->ethernet_typ/1500)/(ethernet->ethernet_typ/1500>0?ethernet->ethernet_typ/1500:1)),ci_sa_vypise);
        vyber_protokolu=0;
    }
    else {
        ieee = (struct ieee_hlavicka*)(packet + *dlzka_ethernetovej_hlavicky);
        if(ieee->ieee_dsap == 0xff) {
            hodnota_zo_suboru=meno_protokolu(subor,'#', ieee->ieee_dsap,ci_sa_vypise);
            vyber_protokolu=1;
        }
        else if(ieee->ieee_dsap == 0xAA){
            hodnota_zo_suboru=meno_protokolu(subor,'#', ieee->ieee_dsap,ci_sa_vypise);
            vyber_protokolu=2;
        }
        else {
            hodnota_zo_suboru=meno_protokolu(subor,'#', ((ethernet->ethernet_typ/1500)/(ethernet->ethernet_typ/1500>0?ethernet->ethernet_typ/1500:1)),ci_sa_vypise);
            //*dlzka_ethernetovej_hlavicky=*dlzka_ethernetovej_hlavicky+5;
            ethernet->ethernet_typ = ieee->ieee_ethernet_typ;
            vyber_protokolu=3;
        }
    }
    return vyber_protokolu;
}

int vypis_menu(){
    int menu;
    printf("----------------------------------------------------------------------------------\n");
    printf("Vyberte o ktory vypis mate zaujem (zadajte cislo):\n");
    printf("1 -Vypis vsetkych komunikacii podla bodu 1\n");
    printf("2 -Vypis vsetkych komunikacii HTTP podla bodu 3a\n");
    printf("3 -Vypis vsetkych komunikacii HTTPS podla bodu 3b\n");
    printf("4 -Vypis vsetkych komunikacii TELNET podla bodu 3c\n");
    printf("5 -Vypis vsetkych komunikacii SSH podla bodu 3d\n");
    printf("6 -Vypis vsetkych FTP riadiace komunikacii podla bodu 3e\n");
    printf("7 -Vypis vsetkych FTP datove komunikacii podla bodu 3f\n");
    printf("8 -Vypis vsetkych komunikacii TFTP podla bodu 3g\n");
    printf("9 -Vypis vsetkych komunikacii ICMP podla bodu 3h\n");
    printf("10 -Vypis vsetkych komunikacii ARP dvojic (request – reply) podla bodu 3i\n");
    printf("11 -Dooimplementacia vypis\n");
    printf("0 -Koniec\n");
    printf("----------------------------------------------------------------------------------\n");
    printf("Zadajte prosim cislo: ");
    scanf("%d",&menu);
    printf("\n");
    return menu;
}

int main(int argc, const char * argv[]) {
    char *meno_suboru ={"trace-1.pcap"};
    char chyba_pcap_suboru[PCAP_ERRBUF_SIZE];   // chyba pri otvoreni pcap suboru
    char **pole_vysielacie_ip = (char**)malloc(sizeof(char*));         // alokacia pola s IP adresamy ktore vysielaju
    struct pcap_pkthdr *pcap_hlavicka;          // hlavicka od pcap
    struct ethernet_hlavicka *ethernet;   // vytvorenie ethernetovej struktury
    struct ip_hlavicka *ip;               // vytvorenie ip struktury
    struct tcp_hlavicka *tcp;             // vytvorenie tcp struktury
    struct udp_hlavicka *udp;             // vytvorenie udp struktury
    struct arp_hlavicka *arp;             // vytvorenie arp struktury
    struct icmp_hlavicka *icmp;           // vytvorenie tcp struktury
    struct ieee_hlavicka *ieee = NULL;            // vytvorenie struktury mimo ethernet
    const u_char *packet;                       // cely packet
    pcap_t *pcap_subor;                         // format pcap suboru
    u_int cislo_ramca = 0;                      // cislo ramca ktory sa spracuva
    FILE *subor;                                // subor (cisla protokolov...)
    long double *velkost_bajtov_IP = (long double*)malloc(sizeof(long double));
    short nova_ip = 0;                          // premenna hovori ci mame novu vysielaciu ip alebo to je jedna zo starych
    int dlzka_ethernetovej_hlavicky = 14;
    int i, vyber_protokolu=-1, dalsi_frame, hodnota_zo_suboru=0, dlzka_ramca=0, vypis_mena=1, menu, pocet_roznych_vysielacich_ip = 0;       // pomocne premenne
    
    int pocet_framov_ku_komunikaciam[11]={0,0,0,0,0,0,0,0,0,0,0};
    
    
    if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
        printf("Nejde otvorit");
    }
    //otvorenie suboru
    if ((subor = fopen("protokol.txt", "r")) == NULL) {
        printf("Neotvoreny subor\n");
    }
    int ix=0;
    while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
        ix++;
        pocet_framov_ku_komunikaciam[0]++;
        dlzka_ethernetovej_hlavicky=14;
        ethernet = (struct ethernet_hlavicka*)(packet);
        ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
        vyber_protokolu = vyber_standart(ethernet, ieee, subor, hodnota_zo_suboru, &dlzka_ethernetovej_hlavicky, packet, 0);
        if(vyber_protokolu==0){
            hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,0);
            //printf("\n%d %d ",ix,ethernet->ethernet_typ);
            if(hodnota_zo_suboru == 2048){
                ip = (struct ip_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                int ip_option = 0;
                if(ip->ip_verzia>69)ip_option = (ip->ip_verzia - 69);
                ip_option = ip_option * 4;
                //printf(" %d ",ip->ip_protokol);
                if(ip->ip_protokol==1)pocet_framov_ku_komunikaciam[9]++; //icmp
                else if (ip->ip_protokol==6){   //tcp
                    tcp = (struct tcp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky + DLZKA_TCP_HLAVICKY + ip_option);
                    tcp->tcp_zdrojovy_port = vymena_bytov(tcp->tcp_zdrojovy_port);
                    tcp->tcp_cielovy_port = vymena_bytov(tcp->tcp_cielovy_port);
                    
                    //printf(" %d %d",tcp->tcp_cielovy_port,tcp->tcp_zdrojovy_port);
                    if(tcp->tcp_cielovy_port == 80 || tcp->tcp_zdrojovy_port == 80){pocet_framov_ku_komunikaciam[2]++;}//printf("\n\t\t\t\t\t\t\t\t\t\t\tnajdene");}
                    if(tcp->tcp_cielovy_port == 443 || tcp->tcp_zdrojovy_port == 443)pocet_framov_ku_komunikaciam[3]++;
                    if(tcp->tcp_cielovy_port == 23 || tcp->tcp_zdrojovy_port == 23)pocet_framov_ku_komunikaciam[4]++;
                    if(tcp->tcp_cielovy_port == 22 || tcp->tcp_zdrojovy_port == 22)pocet_framov_ku_komunikaciam[5]++;
                    if(tcp->tcp_cielovy_port == 21 || tcp->tcp_zdrojovy_port == 21)pocet_framov_ku_komunikaciam[6]++;
                    if(tcp->tcp_cielovy_port == 20 || tcp->tcp_zdrojovy_port == 20)pocet_framov_ku_komunikaciam[7]++;
                }
                else if (ip->ip_protokol==17){  //UDP
                    udp = (struct udp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky + DLZKA_TCP_HLAVICKY + ip_option);
                    udp->udp_zdrojovy_port = vymena_bytov(udp->udp_zdrojovy_port);
                    udp->udp_cielovy_port = vymena_bytov(udp->udp_cielovy_port);
                    if(udp->udp_cielovy_port == 69 || udp->udp_zdrojovy_port == 69)pocet_framov_ku_komunikaciam[8]++;
                }
            }
            else if(hodnota_zo_suboru == 2054){
                arp = (struct arp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                if(arp->arp_operation==1)pocet_framov_ku_komunikaciam[10]++;
            }
        }
    }
    
    
    
    pcap_close(pcap_subor);
    
    while(1){
        int pocet_vypisov = 0;
        cislo_ramca=0;
        menu = vypis_menu();
        if(menu == 0){
            if(subor!=NULL)fclose(subor);  // zatvorenie suboru (cisla portov)
            return 0;
        }
        
        
        
        //---------------------------------------------------------------------
        if(menu == 11){
            char *ip_zdroj;
            int pocet_ramcov=0;
            ip_zdroj = (char *)malloc(16*sizeof(char));
            //otvorenie pcap suboru (offline)
            if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                printf("Nejde otvorit");
            }
            //zistovanie poctu ramcov vvo frame
            while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                pocet_ramcov++;
            }
            if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                printf("Nejde otvorit");
            }
            // cyklus prechadzania celeho suboru 1 x
            *(velkost_bajtov_IP+0)=0;
            while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                dlzka_ramca=0;
                dlzka_ethernetovej_hlavicky=14;
                cislo_ramca++;
                vypis_mena=1;
                //vypis_zaklad(cislo_ramca, pcap_hlavicka->caplen, pcap_hlavicka->len);
                vypis_mena = 0;
                ethernet = (struct ethernet_hlavicka*)(packet);
                ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                vyber_protokolu = vyber_standart(ethernet, ieee, subor, hodnota_zo_suboru, &dlzka_ethernetovej_hlavicky, packet, 0);
                if(vyber_protokolu==0){
                    
                    hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,0);
                    
                    if(hodnota_zo_suboru==2048){ // ak je to IP
                        ip_zdroj = (char *)malloc(16*sizeof(char));
                        //vypis cielovej IP adresy
                        ip = (struct ip_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                        int byte=0,delitel=100;
                        for(i=0;i<15;i++){
                            if(delitel==0){
                                byte++;
                                delitel=100;
                                ip_zdroj[i]='.';
                                i++;
                            }
                            if(byte==4){
                                ip_zdroj[i-1]='\0';
                                break;
                            }
                            if(((ip->ip_cielova[byte]/delitel)%10==0)&&((ip->ip_cielova[byte]/100)%10==0)&&delitel>1){
                                delitel=delitel/10;
                                i--;
                            }
                            else{
                                ip_zdroj[i]=((ip->ip_cielova[byte]/delitel)%10)+'0';
                                delitel=delitel/10;
                            }
                        }
                        nova_ip=0; //hodnota ktora nam zistuje ci dana ip adresa uz je zapisana
                        //if nam zistuje ci uz bola zapisana aspon jedna adresa ak nie tak ju zapise (alokuje)
                        if(pocet_roznych_vysielacich_ip==0){
                            *(pole_vysielacie_ip+0)=ip_zdroj;
                            *(velkost_bajtov_IP+0)=*(velkost_bajtov_IP+0)+1;
                            pocet_roznych_vysielacich_ip++;
                            nova_ip=1;
                        }
                        else{
                            //tento for prejde vsetky adresy a porovna ich s aktualnm v tomto frame
                            for(i=0;i<pocet_roznych_vysielacich_ip;i++){
                                if(strcmp(*(pole_vysielacie_ip + i),ip_zdroj)==0){
                                    *(velkost_bajtov_IP+i)=*(velkost_bajtov_IP+i)+1;
                                    nova_ip=1;
                                }
                            }
                        }
                        // ak hodnota nova_ip je 0 hovori nam o tom ze dana ip adresa este nebola zapisana do pola
                        // zapiseme ju do pola a (stare pole reallokujeme)
                        if(nova_ip==0){
                            pocet_roznych_vysielacich_ip++;
                            pole_vysielacie_ip = (char**)realloc(pole_vysielacie_ip, pocet_roznych_vysielacich_ip*sizeof(char*));
                            pole_vysielacie_ip[pocet_roznych_vysielacich_ip-1]=ip_zdroj;
                            *(velkost_bajtov_IP+(pocet_roznych_vysielacich_ip-1))=1;
                            
                            nova_ip=1;
                        }
                    }
                }
                
                //vypis_mac_addresy(ethernet);
                //ethernet->ethernet_typ=vymena_bytov(ethernet->ethernet_typ);
                //hexa_vypis(pcap_hlavicka->len, packet);
                //ethernet->ethernet_typ=vymena_bytov(ethernet->ethernet_typ);
            }
            
            
            
            
            
            
            //double najviac_bajtov = 0;  //tieto premenne nam pomahaju pri hladani maxima
            //int cislo_ip=0;
            printf("\nIP adresy cielovych uzlov: \n");
            //for nam sluzi na vypisanie vsetkych ip ktore obsahuje pole a hlada nam sucasne adresu s najvacsim poctom odvysielanych bajtov
            for(i=0;i<pocet_roznych_vysielacich_ip;i++){
                printf("\n%s", pole_vysielacie_ip[i]);
                printf(" %.0Lf paketov", velkost_bajtov_IP[i]);
            }
            printf("\n");
            //printf("\n\nAdresa uzla s najvacsim poctom odvysielanych bajtov: \n%s\t%.0Lf bajtov\n\n",pole_vysielacie_ip[cislo_ip],velkost_bajtov_IP[cislo_ip]);
            //for(i=0;i<pocet_roznych_vysielacich_ip;i++){
              //  velkost_bajtov_IP[i]=0;
            //}
            free(*pole_vysielacie_ip);
            free(velkost_bajtov_IP);
            free(ip_zdroj);
            pcap_close(pcap_subor);
        }
        //---------------------------------------------------------------------
        
        
        
        
        
        
        if(menu == 1){
            char *ip_zdroj;
            int pocet_ramcov=0;
            ip_zdroj = (char *)malloc(16*sizeof(char));
            //otvorenie pcap suboru (offline)
            if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                printf("Nejde otvorit");
            }
            //zistovanie poctu ramcov vvo frame
            while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                pocet_ramcov++;
            }
            if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                printf("Nejde otvorit");
            }
            // cyklus prechadzania celeho suboru 1 x
            while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                dlzka_ramca=0;
                dlzka_ethernetovej_hlavicky=14;
                cislo_ramca++;
                vypis_mena=1;
                vypis_zaklad(cislo_ramca, pcap_hlavicka->caplen, pcap_hlavicka->len);
                vypis_mena = 0;
                ethernet = (struct ethernet_hlavicka*)(packet);
                ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                vyber_protokolu = vyber_standart(ethernet, ieee, subor, hodnota_zo_suboru, &dlzka_ethernetovej_hlavicky, packet, 1);
                if(vyber_protokolu==0){
                    
                    hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,0);
                    if(hodnota_zo_suboru==2054){ // ak je to ARP
                        
                        //printf("\t\t\t\t\t\t\t++++++++++++++++cislo ramca %d %.2x %d",cislo_ramca, ethernet->ethernet_typ, hodnota_zo_suboru);
                        ip_zdroj = (char *)malloc(16*sizeof(char));
                        //vypis cielovej IP adresy
                        arp = (struct arp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                        int byte=0,delitel=100;
                        for(i=0;i<15;i++){
                            if(delitel==0){
                                byte++;
                                delitel=100;
                                ip_zdroj[i]='.';
                                i++;
                            }
                            if(byte==4){
                                ip_zdroj[i-1]='\0';
                                break;
                            }
                            if(((arp->arp_zdrojova_protocol_address[byte]/delitel)%10==0)&&((arp->arp_zdrojova_protocol_address[byte]/100)%10==0)&&delitel>1){
                                delitel=delitel/10;
                                i--;
                            }
                            else{
                                ip_zdroj[i]=((arp->arp_zdrojova_protocol_address[byte]/delitel)%10)+'0';
                                delitel=delitel/10;
                            }
                        }
                        nova_ip=0; //hodnota ktora nam zistuje ci dana ip adresa uz je zapisana
                        //if nam zistuje ci uz bola zapisana aspon jedna adresa ak nie tak ju zapise (alokuje)
                        if(pocet_roznych_vysielacich_ip==0){
                            *(pole_vysielacie_ip+0)=ip_zdroj;
                            *(velkost_bajtov_IP+0)=velkost_bytov(pcap_hlavicka->len);
                            pocet_roznych_vysielacich_ip++;
                            nova_ip=1;
                        }
                        else{
                            //tento for prejde vsetky adresy a porovna ich s aktualnm v tomto frame
                            for(i=0;i<pocet_roznych_vysielacich_ip;i++){
                                if(strcmp(*(pole_vysielacie_ip + i),ip_zdroj)==0){
                                    *(velkost_bajtov_IP+i)=*(velkost_bajtov_IP+i)+ velkost_bytov(pcap_hlavicka->len);
                                    nova_ip=1;
                                }
                            }
                        }
                        // ak hodnota nova_ip je 0 hovori nam o tom ze dana ip adresa este nebola zapisana do pola
                        // zapiseme ju do pola a (stare pole reallokujeme)
                        if(nova_ip==0){
                            pocet_roznych_vysielacich_ip++;
                            pole_vysielacie_ip = (char**)realloc(pole_vysielacie_ip, pocet_roznych_vysielacich_ip*sizeof(char*));
                            //printf("\n\n\n----------------------------------------------------------------------------------------%s",ip_zdroj);
                            pole_vysielacie_ip[pocet_roznych_vysielacich_ip-1]=ip_zdroj;
                            *(velkost_bajtov_IP+(pocet_roznych_vysielacich_ip-1))=velkost_bytov(pcap_hlavicka->len);
                            nova_ip=1;
                        }
                    }
                    if(hodnota_zo_suboru==2048){ // ak je to IP
                        ip_zdroj = (char *)malloc(16*sizeof(char));
                        //vypis cielovej IP adresy
                        ip = (struct ip_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                        int byte=0,delitel=100;
                        for(i=0;i<15;i++){
                            if(delitel==0){
                                byte++;
                                delitel=100;
                                ip_zdroj[i]='.';
                                i++;
                            }
                            if(byte==4){
                                ip_zdroj[i-1]='\0';
                                break;
                            }
                            if(((ip->ip_zdrojova[byte]/delitel)%10==0)&&((ip->ip_zdrojova[byte]/100)%10==0)&&delitel>1){
                                delitel=delitel/10;
                                i--;
                            }
                            else{
                                ip_zdroj[i]=((ip->ip_zdrojova[byte]/delitel)%10)+'0';
                                delitel=delitel/10;
                            }
                        }
                        nova_ip=0; //hodnota ktora nam zistuje ci dana ip adresa uz je zapisana
                        //if nam zistuje ci uz bola zapisana aspon jedna adresa ak nie tak ju zapise (alokuje)
                        if(pocet_roznych_vysielacich_ip==0){
                            *(pole_vysielacie_ip+0)=ip_zdroj;
                            *(velkost_bajtov_IP+0)=velkost_bytov(pcap_hlavicka->len);
                            pocet_roznych_vysielacich_ip++;
                            nova_ip=1;
                        }
                        else{
                            //tento for prejde vsetky adresy a porovna ich s aktualnm v tomto frame
                            for(i=0;i<pocet_roznych_vysielacich_ip;i++){
                                if(strcmp(*(pole_vysielacie_ip + i),ip_zdroj)==0){
                                    *(velkost_bajtov_IP+i)=*(velkost_bajtov_IP+i)+velkost_bytov(pcap_hlavicka->len);
                                    nova_ip=1;
                                }
                            }
                        }
                        // ak hodnota nova_ip je 0 hovori nam o tom ze dana ip adresa este nebola zapisana do pola
                        // zapiseme ju do pola a (stare pole reallokujeme)
                        if(nova_ip==0){
                            pocet_roznych_vysielacich_ip++;
                            pole_vysielacie_ip = (char**)realloc(pole_vysielacie_ip, pocet_roznych_vysielacich_ip*sizeof(char*));
                            pole_vysielacie_ip[pocet_roznych_vysielacich_ip-1]=ip_zdroj;
                            *(velkost_bajtov_IP+(pocet_roznych_vysielacich_ip-1))=velkost_bytov(pcap_hlavicka->len);
                            nova_ip=1;
                        }
                    }
                }
                
                vypis_mac_addresy(ethernet);
                ethernet->ethernet_typ=vymena_bytov(ethernet->ethernet_typ);
                hexa_vypis(pcap_hlavicka->len, packet);
                ethernet->ethernet_typ=vymena_bytov(ethernet->ethernet_typ);
            }
            double najviac_bajtov = 0;  //tieto premenne nam pomahaju pri hladani maxima
            int cislo_ip=0;
            printf("IP adresy vysielajucich uzlov: ");
            //for nam sluzi na vypisanie vsetkych ip ktore obsahuje pole a hlada nam sucasne adresu s najvacsim poctom odvysielanych bajtov
            for(i=0;i<pocet_roznych_vysielacich_ip;i++){
                printf("\n%s", pole_vysielacie_ip[i]);
                if(velkost_bajtov_IP[i]>najviac_bajtov){
                    najviac_bajtov=velkost_bajtov_IP[i];
                    cislo_ip=i;
                }
            }
            printf("\n\nAdresa uzla s najvacsim poctom odvysielanych bajtov: \n%s\t%.0Lf bajtov\n\n",pole_vysielacie_ip[cislo_ip],velkost_bajtov_IP[cislo_ip]);
            for(i=0;i<pocet_roznych_vysielacich_ip;i++){
                velkost_bajtov_IP[i]=0;
            }
            free(*pole_vysielacie_ip);
            free(velkost_bajtov_IP);
            free(ip_zdroj);
            pcap_close(pcap_subor);
        }
        
        
        
        if(menu>1 && menu <8){
            int protokol=0;
            int pocet_daneho_protokolu=0;
            switch(menu){
                case 2:{protokol=80;printf("\nVypis HTTP komunikacie :\n");pocet_vypisov=pocet_framov_ku_komunikaciam[menu];}break;
                case 3:{protokol=443;printf("\nVypis HTTPS komunikacie :\n");pocet_vypisov=pocet_framov_ku_komunikaciam[menu];}break;
                case 4:{protokol=23;printf("\nVypis Telnet komunikacie :\n");pocet_vypisov=pocet_framov_ku_komunikaciam[menu];}break;
                case 5:{protokol=22;printf("\nVypis SSH komunikacie :\n");pocet_vypisov=pocet_framov_ku_komunikaciam[menu];}break;
                case 6:{protokol=21;printf("\nVypis FTP-riadenie komunikacie :\n");pocet_vypisov=pocet_framov_ku_komunikaciam[menu];}break;
                case 7:{protokol=20;printf("\nVypis FTP-data komunikacie :\n");pocet_vypisov=pocet_framov_ku_komunikaciam[menu];}break;
            }
            if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                printf("Nejde otvorit");
            }
            cislo_ramca=0;
            // cyklus prechadzania celeho suboru HTTP
            while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                vyber_protokolu=-1;
                dlzka_ramca=0;
                cislo_ramca++;
                dlzka_ethernetovej_hlavicky=14;
                //vytvarania struktur ku danemu ramcu
                ethernet = (struct ethernet_hlavicka*)(packet);
                ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                vypis_mena=0;
                vyber_protokolu = vyber_standart(ethernet, ieee, subor, hodnota_zo_suboru, &dlzka_ethernetovej_hlavicky, packet, 0);
                if(vyber_protokolu!=0)continue;
                if(vyber_protokolu==0){
                    hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,vypis_mena);
                    if(hodnota_zo_suboru==2048){ // ak je to IP
                        //vypis cielovej IP adresy
                        ip = (struct ip_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                        hodnota_zo_suboru=0;
                        hodnota_zo_suboru=meno_protokolu(subor,'-', ip->ip_protokol,vypis_mena);
                        if(hodnota_zo_suboru==6){ //ak je to TCP
                            int ip_option = 0;
                            if(ip->ip_verzia>69)ip_option = (ip->ip_verzia - 69);
                            ip_option = ip_option * 4;
                            tcp = (struct tcp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky + DLZKA_TCP_HLAVICKY + ip_option);
                            tcp->tcp_zdrojovy_port = vymena_bytov(tcp->tcp_zdrojovy_port);
                            tcp->tcp_cielovy_port = vymena_bytov(tcp->tcp_cielovy_port);
                            if(tcp->tcp_cielovy_port!=protokol&&tcp->tcp_zdrojovy_port!=protokol)continue;
                            pocet_daneho_protokolu++;
                            if(pocet_daneho_protokolu<=10 || (pocet_daneho_protokolu > (pocet_vypisov-10)))
                            {
                                //printf("\n----------------------------------------------------------------------pocet_dane_vysk - %d  pocet_vypisov- %d",pocet_daneho_protokolu,pocet_vypisov);
                                vypis_zaklad(cislo_ramca,  pcap_hlavicka->caplen, pcap_hlavicka->len);
                                hodnota_zo_suboru=meno_protokolu(subor,'#', ((ethernet->ethernet_typ/1500)/(ethernet->ethernet_typ/1500>0?ethernet->ethernet_typ/1500:1)),1);
                                vyber_protokolu=1;
                                vypis_mac_addresy(ethernet);
                                hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,1);
                                vypis_ip(ip);
                                hodnota_zo_suboru=meno_protokolu(subor,'-', ip->ip_protokol,1);
                                vypis_tcp_protocol(tcp);
                                meno_portu(subor, tcp->tcp_zdrojovy_port,tcp->tcp_cielovy_port,'/');
                                tcp->tcp_zdrojovy_port = vymena_bytov(tcp->tcp_zdrojovy_port);
                                tcp->tcp_cielovy_port = vymena_bytov(tcp->tcp_cielovy_port);
                                ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                                hexa_vypis(pcap_hlavicka->len, packet);
                            }
                        }
                    }
                }
            }
            pcap_close(pcap_subor);
            //printf("\n-------------------------------------------------------------------------%d\n",pocet_vypisov);
        }
        
        
        
        
        if(menu == 8){
            pocet_vypisov = pocet_framov_ku_komunikaciam[menu];
            int pocet_daneho_protokolu=0;
            printf("\nVypis THTP komunikacie :\n");
            if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                printf("Nejde otvorit");
            }
            cislo_ramca=0;
            int protokol=69;
            while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                dlzka_ramca=0;
                cislo_ramca++;
                dlzka_ethernetovej_hlavicky=14;
                //vytvarania struktur ku danemu ramcu
                ethernet = (struct ethernet_hlavicka*)(packet);
                ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                vypis_mena=0;
                vyber_protokolu = vyber_standart(ethernet, ieee, subor, hodnota_zo_suboru, &dlzka_ethernetovej_hlavicky, packet, 0);
                if(vyber_protokolu!=0)continue;
                if(vyber_protokolu==0){
                    hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,vypis_mena);
                    if(hodnota_zo_suboru==2048){ // ak je to IP
                        //vypis cielovej IP adresy
                        ip = (struct ip_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                        hodnota_zo_suboru=0;
                        hodnota_zo_suboru=meno_protokolu(subor,'-', ip->ip_protokol,vypis_mena);
                        if(hodnota_zo_suboru==17){ //ak je to UDP
                            int ip_option = 0;
                            if(ip->ip_verzia>69)ip_option = (ip->ip_verzia - 69);
                            ip_option = ip_option * 4;
                            udp = (struct udp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky + DLZKA_TCP_HLAVICKY + ip_option);
                            udp->udp_zdrojovy_port = vymena_bytov(udp->udp_zdrojovy_port);
                            udp->udp_cielovy_port = vymena_bytov(udp->udp_cielovy_port);
                            if(udp->udp_zdrojovy_port!=protokol&&udp->udp_cielovy_port!=protokol)continue;
                            pocet_daneho_protokolu++;
                            if(pocet_daneho_protokolu<=10 || pocet_daneho_protokolu>pocet_vypisov-10)
                            {
                                vypis_zaklad(cislo_ramca,  pcap_hlavicka->caplen, pcap_hlavicka->len);
                                hodnota_zo_suboru=meno_protokolu(subor,'#', ((ethernet->ethernet_typ/1500)/(ethernet->ethernet_typ/1500>0?ethernet->ethernet_typ/1500:1)),1);
                                vyber_protokolu=1;
                                vypis_mac_addresy(ethernet);
                                meno_protokolu(subor,'|', ethernet->ethernet_typ,1);
                                vypis_ip(ip);
                                meno_protokolu(subor,'-', ip->ip_protokol,1);
                                vypis_udp_protocol(udp);
                                meno_portu(subor, udp->udp_zdrojovy_port,udp->udp_cielovy_port,'<');
                                udp->udp_zdrojovy_port = vymena_bytov(udp->udp_zdrojovy_port);
                                udp->udp_cielovy_port = vymena_bytov(udp->udp_cielovy_port);
                                ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                                
                                hexa_vypis(pcap_hlavicka->len, packet);
                            }
                        }
                    }
                }
            }
            //printf("\n-------------------------------------------------------------------------%d\n",pocet_vypisov);
            pcap_close(pcap_subor);
        }
        
        
        if(menu == 9){
            pocet_vypisov = pocet_framov_ku_komunikaciam[menu];
            int pocet_daneho_protokolu=0;
            if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                printf("Nejde otvorit");
            }
            printf("\nVypis ICMP komunikacie :\n");
            cislo_ramca=0;
            // cyklus prechadzania celeho suboru HTTP
            while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                dlzka_ramca=0;
                cislo_ramca++;
                dlzka_ethernetovej_hlavicky=14;
                //vytvarania struktur ku danemu ramcu
                ethernet = (struct ethernet_hlavicka*)(packet);
                ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                vypis_mena=0;
                vyber_protokolu = vyber_standart(ethernet, ieee, subor, hodnota_zo_suboru, &dlzka_ethernetovej_hlavicky, packet, 0);
                if(vyber_protokolu!=0)continue;
                if(vyber_protokolu==0){
                    hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,vypis_mena);
                    if(hodnota_zo_suboru==2048){ // ak je to IP
                        //vypis cielovej IP adresy
                        ip = (struct ip_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                        hodnota_zo_suboru=0;
                        hodnota_zo_suboru=meno_protokolu(subor,'-', ip->ip_protokol,vypis_mena);
                        if(hodnota_zo_suboru==1){ //ak je to ICMP
                            int ip_option = 0;
                            if(ip->ip_verzia>69)ip_option = (ip->ip_verzia - 69);
                            ip_option = ip_option * 4;
                            icmp = (struct icmp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky + DLZKA_TCP_HLAVICKY + ip_option);
                            pocet_daneho_protokolu++;
                            if(pocet_daneho_protokolu<=10 || pocet_daneho_protokolu>(pocet_vypisov-10))
                            {
                                vypis_zaklad(cislo_ramca,  pcap_hlavicka->caplen, pcap_hlavicka->len);
                                hodnota_zo_suboru=meno_protokolu(subor,'#', ((ethernet->ethernet_typ/1500)/(ethernet->ethernet_typ/1500>0?ethernet->ethernet_typ/1500:1)),1);
                                vyber_protokolu=1;
                                vypis_mac_addresy(ethernet);
                                hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,1);
                                vypis_ip(ip);
                                printf("%x",icmp->icmp_type);
                                
                                hodnota_zo_suboru=meno_protokolu(subor,'-', ip->ip_protokol,1);
                                hodnota_zo_suboru=meno_protokolu(subor,'\\', icmp->icmp_type,1);
                                ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                                hexa_vypis(pcap_hlavicka->len, packet);
                            }
                        }
                    }
                }
            }
            //printf("\n-------------------------------------------------------------------------%d\n",pocet_vypisov);
            pcap_close(pcap_subor);
        }
        
        if(menu == 10){
            int cislo_arp_packetu=0,komunikacia=0,pocet_ramcov=0,vypnutie=0;
            u_char ip_arp_request_zdroj[DLZKA_IP_ADD];
            u_char ip_arp_request_ciel[DLZKA_IP_ADD];
            u_char mac_arp_request[DLZKA_MAC_ADD];
            if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                printf("Nejde otvorit");
            }
            while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                pocet_ramcov++;
            }
            pcap_close(pcap_subor);
            printf("\nVypis ARP dvojic :\n");
            while (1){
                if(vypnutie==1)break;
                cislo_ramca=0;
                if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                    printf("Nejde otvorit");
                }
                // cyklus prechadzania celeho suboru arp
                while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                    if(cislo_arp_packetu==pocet_ramcov)vypnutie=1;
                    cislo_ramca++;
                    if(cislo_arp_packetu < cislo_ramca){
                        dlzka_ramca=0;
                        cislo_arp_packetu++;
                        dlzka_ethernetovej_hlavicky=14;
                        //vytvarania struktur ku danemu ramcu
                        ethernet = (struct ethernet_hlavicka*)(packet);
                        ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                        vypis_mena=0;
                        vyber_protokolu = vyber_standart(ethernet, ieee, subor, hodnota_zo_suboru, &dlzka_ethernetovej_hlavicky, packet, 0);
                        if(vyber_protokolu!=0)continue;
                        if(vyber_protokolu==0){
                            hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,vypis_mena);
                            if(hodnota_zo_suboru==2054){ // ak je to ARP
                                arp = (struct arp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                                arp->arp_operation=vymena_bytov(arp->arp_operation);
                                if(arp->arp_operation==1){
                                    komunikacia++;
                                    printf("Komunikacia c. %d",komunikacia);
                                    hodnota_zo_suboru=meno_protokolu(subor, '*', arp->arp_operation, 1);
                                    printf(", IP adresa : %d.%d.%d.%d,\tMAC: ???\n",arp->arp_target_protocol_address[0],arp->arp_target_protocol_address[1],arp->arp_target_protocol_address[2],arp->arp_target_protocol_address[3]);
                                    printf("Zdrojovy IP: %d.%d.%d.%d,\tCielova IP: %d.%d.%d.%d\n",arp->arp_zdrojova_protocol_address[0],arp->arp_zdrojova_protocol_address[1],arp->arp_zdrojova_protocol_address[2],arp->arp_zdrojova_protocol_address[3],arp->arp_target_protocol_address[0],arp->arp_target_protocol_address[1],arp->arp_target_protocol_address[2],arp->arp_target_protocol_address[3]);
                                    vypis_zaklad(cislo_ramca,  pcap_hlavicka->caplen, pcap_hlavicka->len);
                                    hodnota_zo_suboru=meno_protokolu(subor,'#', ((ethernet->ethernet_typ/1500)/(ethernet->ethernet_typ/1500>0?ethernet->ethernet_typ/1500:1)),1);
                                    vypis_mac_addresy(ethernet);
                                    ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                                    hexa_vypis(pcap_hlavicka->len, packet);
                                    for(i=0;i<DLZKA_MAC_ADD;i++)mac_arp_request[i]=arp->arp_zdrojova_hw_address[i];
                                    for(i=0;i<DLZKA_IP_ADD;i++){
                                        ip_arp_request_zdroj[i]=arp->arp_zdrojova_protocol_address[i];
                                        ip_arp_request_ciel[i]=arp->arp_target_protocol_address[i];
                                    }
                                    pcap_close(pcap_subor);
                                    if ((pcap_subor = pcap_open_offline(meno_suboru, chyba_pcap_suboru)) == NULL){
                                        printf("Nejde otvorit");
                                    }
                                    while ((dalsi_frame = pcap_next_ex(pcap_subor, &pcap_hlavicka, &packet)) >= 0){
                                        cislo_ramca++;
                                        dlzka_ethernetovej_hlavicky=14;
                                        //vytvarania struktur ku danemu ramcu
                                        ethernet = (struct ethernet_hlavicka*)(packet);
                                        ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                                        vypis_mena=0;
                                        vyber_protokolu = vyber_standart(ethernet, ieee, subor, hodnota_zo_suboru, &dlzka_ethernetovej_hlavicky, packet, 0);
                                        if(vyber_protokolu!=0)continue;
                                        if(vyber_protokolu==0){
                                            hodnota_zo_suboru=meno_protokolu(subor,'|', ethernet->ethernet_typ,vypis_mena);
                                            if(hodnota_zo_suboru==2054){ // ak je to ARP
                                                arp = (struct arp_hlavicka*)(packet + dlzka_ethernetovej_hlavicky);
                                                arp->arp_operation=vymena_bytov(arp->arp_operation);
                                                if(arp->arp_operation==2){
                                                    int help=0;
                                                    for(i=0;i<DLZKA_IP_ADD;i++){
                                                        if(ip_arp_request_ciel[i]!=arp->arp_zdrojova_protocol_address[i]&&ip_arp_request_zdroj[i]!=arp->arp_target_protocol_address[i])help=1;
                                                    }
                                                    for(i=0;i<DLZKA_MAC_ADD;i++){
                                                        if(mac_arp_request[i]!=arp->arp_target_hw_address[i])help=1;
                                                    }
                                                    if(help==1)continue;
                                                    hodnota_zo_suboru=meno_protokolu(subor, '*', arp->arp_operation, 1);
                                                    printf(", IP adresa : %d.%d.%d.%d,\tMAC: ",arp->arp_zdrojova_protocol_address[0],arp->arp_zdrojova_protocol_address[1],arp->arp_zdrojova_protocol_address[2],arp->arp_zdrojova_protocol_address[3]);
                                                    for(i=0;i<DLZKA_MAC_ADD;i++)printf("%.2X ",arp->arp_zdrojova_hw_address[i]);
                                                    printf("\nZdrojovy IP: %d.%d.%d.%d,\tCielova IP: %d.%d.%d.%d\n",arp->arp_zdrojova_protocol_address[0],arp->arp_zdrojova_protocol_address[1],arp->arp_zdrojova_protocol_address[2],arp->arp_zdrojova_protocol_address[3],arp->arp_target_protocol_address[0],arp->arp_target_protocol_address[1],arp->arp_target_protocol_address[2],arp->arp_target_protocol_address[3]);
                                                    vypis_zaklad(cislo_ramca,  pcap_hlavicka->caplen, pcap_hlavicka->len);
                                                    hodnota_zo_suboru=meno_protokolu(subor,'#', ((ethernet->ethernet_typ/1500)/(ethernet->ethernet_typ/1500>0?ethernet->ethernet_typ/1500:1)),1);
                                                    vypis_mac_addresy(ethernet);
                                                    ethernet->ethernet_typ = vymena_bytov(ethernet->ethernet_typ);
                                                    hexa_vypis(pcap_hlavicka->len, packet);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                pcap_close(pcap_subor);
            }
        }
    }
}


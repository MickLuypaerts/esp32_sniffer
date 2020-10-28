#include "mbedtls/md.h"
#include <esp_wifi.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_WIFI_CHANNEL 13
#define MAC_ADDRESS_SIZE 13
#define TABLE_SIZE 10

typedef struct
{
    unsigned frame_ctrl: 16;
    unsigned duration: 16;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    unsigned seq_control: 16;
    uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct 
{
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_ieee80211_packet_t;

typedef struct node_t
{
    char* mac;
    struct node_t* next;
} node_t;

uint8_t wifi_channel = 1;

inline void setup_WiFi() __attribute__((always_inline));

node_t** hash_table;


void setup()
{
    Serial.begin(115200);
    setup_WiFi();
    hash_table = create_hash_table();
}

void loop()
{
    delay(1000);
    if (wifi_channel > MAX_WIFI_CHANNEL)
    {
        wifi_channel = 1;
    }
    reset_hash_table(hash_table);
    esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
    wifi_channel++;
}

// WIFI functions
void setup_WiFi()
{
    const wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};

    wifi_init_config_t ctg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&ctg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
}

void convert_to_char(char* macAddress, const uint8_t addr[6])
{
    for (int i = 0; i < 6; i++)
    {
        char buff[3];
        sprintf(buff, "%02x", addr[i]);
        strncat(macAddress, buff, 3);
    }
}

void sha256_hash(const char* macAddr)
{
    byte shaResult[32];
    const size_t payloadLenght = strlen(macAddr);

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *) macAddr, payloadLenght);
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);


    char hashedMac[65] = "";
    for (int i = 0; i < sizeof(shaResult); i++)
    {
        char str[3];
        sprintf(str, "%02x", (int)shaResult[i]);
        strcat(hashedMac, str);
    }
    printf("Hashed mac: %s", hashedMac);
}


void sniffer(void* buf, wifi_promiscuous_pkt_type_t type)
{
    char mac[13] = "";

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t*)buf;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *) ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;


    convert_to_char(mac, hdr->addr2);

    if(find_node_in_hash_table(hash_table,mac) != 1)
    {
        add_to_hash_table(hash_table, mac);
        sha256_hash(mac);
        printf("\tMAC: %X:%X:%X:%X:%X:%X\tRSSI: %i\tchannel: %i\n", hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5], ppkt->rx_ctrl.rssi, ppkt->rx_ctrl.channel);
    }
}

// Hash table functions
node_t** create_hash_table(void)
{
    node_t** hash_table = (struct node_t**)malloc(sizeof(struct node_t) * TABLE_SIZE);

    for(int i = 0; i < TABLE_SIZE; i++)
    {
        hash_table[i] = NULL;
    }
    return hash_table;
}

unsigned int hash(const char* mac)
{
    unsigned int mac_hash = 0;
    for(int i = 0; i < MAC_ADDRESS_SIZE; i++)
    {
        mac_hash = mac_hash + mac[i];
    }
    return mac_hash % TABLE_SIZE;
}


void add_to_hash_table(node_t** hash_table, char* mac)
{
    if(find_node_in_hash_table(hash_table, mac) != 1)
    {
        unsigned int mac_hash = hash(mac);
        add_link_to_hash_table_node(&hash_table[mac_hash], mac);
    }
    else
    {
        
        printf("\nmac: %s already in hash table\n", mac);
    } 
}


void add_link_to_hash_table_node(node_t** head, char* mac)
{
    node_t* new_node = (struct node_t*)malloc(sizeof(node_t));
    new_node->mac = (char*)malloc(sizeof(char) * MAC_ADDRESS_SIZE);
    strcpy(new_node->mac, mac);
    new_node->next = NULL;

    node_t* last = *head;

    if(*head == NULL)
    {
        *head = new_node;
        return;
    }
    while(last->next != NULL)
    {
        last = last->next;
    }
    last->next = new_node;
    return;
}

bool find_node_in_hash_table(node_t** hash_table, char* mac)
{
    unsigned int mac_hash = hash(mac);
    node_t* tmp = hash_table[mac_hash];
    while(tmp != NULL)
    {
        if(strcmp(tmp->mac, mac) == 0)
        {
            return true;
        }
        tmp = tmp->next;
    }
    return false;
}

void reset_hash_table(node_t** hash_table)
{
    for(int i = 0; i < TABLE_SIZE; i++)
    {
        node_t* tmp;
        node_t* head = hash_table[i];

        while(head != NULL)
        {
            tmp = head;
            head = head->next;
            free(tmp);
        }
        hash_table[i] = NULL;
    }
}

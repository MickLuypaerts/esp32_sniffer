#include <esp_wifi.h>
#include "mbedtls/md.h"
#include "structures.h"

#define MAX_WIFI_CHANNEL 13
uint8_t wifi_channel = 1;

inline void setup_WiFi() __attribute__((always_inline));


void convert_to_char(char* macAddress, const uint8_t addr[6])
{
  for(int i = 0; i < 6; i++)
  {
    char buff[3];
    sprintf(buff, "%02x", addr[i]);
    strncat(macAddress, buff, 3);
  }
}

void hash_func(const char* macAddr) 
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
    Serial.print("Hashed mac: ");
    for(int i = 0; i < sizeof(shaResult); i++) 
    {
        char str[3];
        sprintf(str, "%02x", (int)shaResult[i]);
        strcat(hashedMac, str);
    }
    Serial.print(hashedMac);
}


void sniffer(void* buf, wifi_promiscuous_pkt_type_t type)
{
    char cMacAddress[13] = "";
    static char lMacAddress[13] = "";

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t*)buf;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *) ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;


    convert_to_char(cMacAddress, hdr->addr2);
    if(strcmp(cMacAddress, lMacAddress)) // TODO: better filtering 
    {
        strcpy(lMacAddress, cMacAddress);
        hash_func(cMacAddress);
        printf("\tMAC: %X:%X:%X:%X:%X:%X\tRSSI: %i\tchannel: %i\n", hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5], ppkt->rx_ctrl.rssi, ppkt->rx_ctrl.channel);
    }
}

void setup()
{
    Serial.begin(115200);     
    setup_WiFi();
}

void loop()
{
    delay(1000);
    if (wifi_channel > MAX_WIFI_CHANNEL)
    {
        wifi_channel = 1;
    }
    esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
    wifi_channel++;
}


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

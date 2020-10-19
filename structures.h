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

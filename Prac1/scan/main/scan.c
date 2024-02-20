* Scan Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/*
    This example shows how to scan for available set of APs.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "driver/uart.h"

#include "esp_vfs.h"
#include "esp_vfs_dev.h"


#define DEFAULT_SCAN_LIST_SIZE 7
#define TIMES_AVG_RSSI 5
#define UART_NUM UART_NUM_1

void connect_to_wifi(const char*,const char*);
void displaySignalLeds(int level);
int askAgain();
int getWorstRSSI();
int getBestRSSI();
int get_level_among_aps();
int avg_current_rssi();
int get_actual_rssi();
static void print_cipher_type(int pairwise_cipher, int group_cipher);
static void print_auth_mode(int authmode);

// #if CONFIG_FREERTOS_UNICORE
//   static const BaseType_t app_cpu = 0;
// #else
//   static const BaseType_t app_cpu = 1;
// #endif

// Settings
// static const uint8_t buf_len = 100;

// Globals
static char *msg_ptr = NULL;
static volatile uint8_t msg_flag = 0;

static const char *TAG = "scan";
wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];

static void print_auth_mode(int authmode){
    switch (authmode) {
    case WIFI_AUTH_OPEN:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_OPEN");
        break;
    case WIFI_AUTH_OWE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_OWE");
        break;
    case WIFI_AUTH_WEP:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WEP");
        break;
    case WIFI_AUTH_WPA_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA_PSK");
        break;
    case WIFI_AUTH_WPA2_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_PSK");
        break;
    case WIFI_AUTH_WPA_WPA2_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA_WPA2_PSK");
        break;
    case WIFI_AUTH_ENTERPRISE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_ENTERPRISE");
        break;
    case WIFI_AUTH_WPA3_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_PSK");
        break;
    case WIFI_AUTH_WPA2_WPA3_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_WPA3_PSK");
        break;
    case WIFI_AUTH_WPA3_ENT_192:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_ENT_192");
        break;
    default:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_UNKNOWN");
        break;
    }
}

static void print_cipher_type(int pairwise_cipher, int group_cipher){
    switch (pairwise_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_NONE");
        break;
    case WIFI_CIPHER_TYPE_WEP40:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP40");
        break;
    case WIFI_CIPHER_TYPE_WEP104:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP104");
        break;
    case WIFI_CIPHER_TYPE_TKIP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP");
        break;
    case WIFI_CIPHER_TYPE_CCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_CCMP");
        break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
        break;
    case WIFI_CIPHER_TYPE_AES_CMAC128:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_AES_CMAC128");
        break;
    case WIFI_CIPHER_TYPE_SMS4:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_SMS4");
        break;
    case WIFI_CIPHER_TYPE_GCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_GCMP");
        break;
    case WIFI_CIPHER_TYPE_GCMP256:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_GCMP256");
        break;
    default:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
        break;
    }

    switch (group_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_NONE");
        break;
    case WIFI_CIPHER_TYPE_WEP40:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_WEP40");
        break;
    case WIFI_CIPHER_TYPE_WEP104:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_WEP104");
        break;
    case WIFI_CIPHER_TYPE_TKIP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_TKIP");
        break;
    case WIFI_CIPHER_TYPE_CCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_CCMP");
        break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
        break;
    case WIFI_CIPHER_TYPE_SMS4:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_SMS4");
        break;
    case WIFI_CIPHER_TYPE_GCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_GCMP");
        break;
    case WIFI_CIPHER_TYPE_GCMP256:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_GCMP256");
        break;
    default:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
        break;
    }
}

/* Initialize Wi-Fi as sta and set scan method */
static void wifi_initialize(void){
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

}
static void wifi_scan(void)
{
    
    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_scan_start(NULL, true);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    printf("Redes encontradas = %u\n", ap_count);
    

    for (int i = 0; (i < DEFAULT_SCAN_LIST_SIZE) && (i < ap_count); i++) {
        printf("%d.- SSID \t\t%s con RSSI: %d ", i+1,ap_info[i].ssid, ap_info[i].rssi);
        print_auth_mode(ap_info[i].authmode);

    }
    // printf("\nSelecciona la red a la que te quieres conectar: ");
    // int selected_network;
    // scanf("%d", &selected_network);
    // if (selected_network > 0 && selected_network <= ap_count) {
    //     char ssid[32];
    //     char password[64];
    //     strcpy(ssid, (char*)ap_info[selected_network-1].ssid);
    //     printf("SSID: %s\n", ssid);
    //     printf("Password: ");
        // //spinlock to read from the serial port of the ESP32
        // while (msg_flag == 0) {
        //     vTaskDelay(100 / portTICK_PERIOD_MS);
        // }

        // strcpy(password, msg_ptr);
        
    // } else {
    //     ESP_LOGE(TAG, "Red no encontrada");
        // }


}

void app_main(void)
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    
    ESP_ERROR_CHECK( ret );
    wifi_initialize();
    wifi_scan();
    connect_to_wifi("INFINITUM5169", "Frecuencia10#");
    do{
        wifi_scan();
        //Already connected to wifi
        displaySignalLeds(get_level_among_aps());
        
    }while(1);
}

int get_actual_rssi() {
    wifi_ap_record_t aux_ap_info;
    esp_err_t ret = esp_wifi_sta_get_ap_info(&aux_ap_info);
    if (ret == ESP_OK) {
        return (aux_ap_info.rssi);
    } else {
        return 0;
    }
}

int avg_current_rssi() {
    int rssi = 0;
    for (int i = 0; i < TIMES_AVG_RSSI; i++) {
        rssi += get_actual_rssi();
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    return rssi / TIMES_AVG_RSSI;
}

int get_level_among_aps(){
    int rssi = avg_current_rssi();
    int best_rssi = getBestRSSI();
    int worst_rssi = getWorstRSSI();
    int steps = (best_rssi - worst_rssi) / 3;
    if (rssi > best_rssi - steps) {
        return 3;
    } else if (rssi > best_rssi - 2 * steps) {
        return 2;
    } else {
        return 1;
    }
}

int getBestRSSI() {
    int best_rssi = -100;
    for (int i = 0; i < DEFAULT_SCAN_LIST_SIZE; i++) {
        if (ap_info[i].rssi > best_rssi) {
            best_rssi = ap_info[i].rssi;
        }
    }
    return best_rssi;
}

int getWorstRSSI() {
    int worst_rssi = 0;
    for (int i = 0; i < DEFAULT_SCAN_LIST_SIZE; i++) {
        if (ap_info[i].rssi < worst_rssi) {
            worst_rssi = ap_info[i].rssi;
        }
    }
    return worst_rssi;
}
//shows the level of the wifi signal with 3 leds via gpio
void displaySignalLeds(int level){
    if (level == 1) {
        //turn on led 1
        printf("Led 1 encendido");
    } else if (level == 2) {
        //turn on led 1 and 2
        printf("Led 1 y 2 encendidos");
    } else {
        printf("Led 1, 2 y 3 encendidos");
    }
}
void connect_to_wifi(const char *ssid, const char *password) {
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "",
            .password = "",
        },
    };
    strcpy((char*)wifi_config.sta.ssid, ssid);
    strcpy((char*)wifi_config.sta.password, password);

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());
}

// void readSerial(void *parameters) {

//   char c;
//   char buf[buf_len];
//   uint8_t idx = 0;

//   // Clear whole buffer
//   memset(buf, 0, buf_len);
  
//   // Loop forever
//   while (!msg_flag) {

//     // Read cahracters from serial
//     if (Serial.available() > 0) {
//       c = Serial.read();

//       // Store received character to buffer if not over buffer limit
//       if (idx < buf_len - 1) {
//         buf[idx] = c;
//         idx++;
//       }

//       // Create a message buffer for print task
//       if (c == '\n') {

//         // The last character in the string is '\n', so we need to replace
//         // it with '\0' to make it null-terminated
//         buf[idx - 1] = '\0';

//         // Try to allocate memory and copy over message. If message buffer is
//         // still in use, ignore the entire message.
//         if (msg_flag == 0) {
//           msg_ptr = (char *)pvPortMalloc(idx * sizeof(char));

//           // If malloc returns 0 (out of memory), throw an error and reset
//           configASSERT(msg_ptr);

//           // Copy message
//           memcpy(msg_ptr, buf, idx);

//           // Notify other task that message is ready
//           msg_flag = 1;
//         }

//         // Reset receive buffer and index counter
//         memset(buf, 0, buf_len);
//         idx = 0;
//       }
//     }
//   }
// }

// char getchar_rx() {
//     uint8_t data;
//     int len = uart_read_bytes(UART_NUM, &data, 1, portMAX_DELAY);
//     if (len > 0) {
//         return (char)data;
//     } else {
//         return '\0'; // Return null character if no data is read
//     }
// }

// void configure_uart() {
//     // Configuration for the UART port
//     uart_config_t uart_config = {
//         .baud_rate = 115200,
//         .data_bits = UART_DATA_8_BITS,
//         .parity = UART_PARITY_DISABLE,
//         .stop_bits = UART_STOP_BITS_1,
//         .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
//     };
//     ESP_ERROR_CHECK(uart_param_config(UART_NUM, &uart_config));

//     // Install UART driver using an event queue here if needed

//     // Set UART pins
//     ESP_ERROR_CHECK(uart_set_pin(UART_NUM, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

//     // Install the UART driver for the USB CDC interface
//     esp_vfs_dev_uart_use_driver(UART_NUM);
// }
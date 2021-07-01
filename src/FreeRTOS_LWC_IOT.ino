#
// Include the necessary libraries
#include <Arduino.h>
#include <SoftwareSerial.h>
#include <Sds011.h>
#include <ArduinoJson.h>
#include <MD5Builder.h>
#include <HTTPClient.h>
#include "ascon-aead.h"
#include "WiFi.h"
#include "time.h"

extern "C" {
#include "crypto/base64.h"
}

//SDS011
//////////////////////////////////////////////////
#define SDS_PIN_RX 16
#define SDS_PIN_TX 17

#ifdef ESP32
HardwareSerial& serialSDS(Serial2);
Sds011Async< HardwareSerial > sds011(serialSDS);
#endif

constexpr int pm_tablesize = 20;
int pm25_table[pm_tablesize];
int pm10_table[pm_tablesize];

bool is_SDS_running = true;
static float mpm10 = 0.0f;
static float mpm25 = 0.0f;
/////////////////////////////////////////////////

#define MAX_DATA_SIZE 12800
#define MAX_TAG_SIZE 32
static unsigned char const key[17]   = "IOT_LWC_ASCON---";
static unsigned char nonce[17] = "IOT_LWC_ASCON---";
static unsigned char plaintext[MAX_DATA_SIZE];
static unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];
static unsigned char associated[33]   = "AABBCCDDEEFF";
static String mac_address;
static String ip_address;
static String encodedstr;
static int numconnections = 0;
static bool connectState = false;
static bool registerState = false;
static String endpoint = "http://54.208.126.98:8000";

const char* ntpServer = "pool.ntp.org";
const long  gmtOffset_sec = -18000;
const int   daylightOffset_sec = 0;
static char timeStamp[20] = "0000-00-00 00:00:00";

#define WIFI_NETWORK "FAMILIA_LV"
#define WIFI_PASSWORD "pavic2016"
#define WIFI_TIMEOUT_MS 20000 // 20 second WiFi connection timeout
#define WIFI_RECOVER_TIME_MS 30000 // Wait 30 seconds after a failed connection attempt

void start_SDS() {
    Serial.println("Start wakeup SDS011");

    if (sds011.set_sleep(false)) { is_SDS_running = true; }

    Serial.println("End wakeup SDS011");
}

void stop_SDS() {
    Serial.println("Start sleep SDS011");

    if (sds011.set_sleep(true)) { is_SDS_running = false; }

    Serial.println("End sleep SDS011");
}

void doMeasure()
{
    // Per manufacturer specification, place the sensor in standby to prolong service life.
    // At an user-determined interval (here 210s down plus 30s duty = 4m), run the sensor for 30s.
    // Quick response time is given as 10s by the manufacturer, thus the library drops the
    // measurements obtained during the first 10s of each run.

    constexpr uint32_t down_s = 210;

    stop_SDS();
    Serial.print("stopped SDS011 (is running = ");
    Serial.print(is_SDS_running);
    Serial.println(")");

    uint32_t deadline = millis() + down_s * 1000;
    while (static_cast<int32_t>(deadline - millis()) > 0) {
        delay(1000);
        Serial.println(static_cast<int32_t>(deadline - millis()) / 1000);
        sds011.perform_work();
    }

    constexpr uint32_t duty_s = 30;

    start_SDS();
    Serial.print("started SDS011 (is running = ");
    Serial.print(is_SDS_running);
    Serial.println(")");

    sds011.on_query_data_auto_completed([](int n) {
        Serial.println("Begin Handling SDS011 query data");
        int pm25;
        int pm10;
        Serial.print("n = "); Serial.println(n);
        if (sds011.filter_data(n, pm25_table, pm10_table, pm25, pm10) &&
            !isnan(pm10) && !isnan(pm25)) {
            Serial.print("PM10: ");
            Serial.println(float(pm10) / 10);
            Serial.print("PM2.5: ");
            Serial.println(float(pm25) / 10);
            mpm10 = float(pm10) / 10;
            mpm25 = float(pm25) / 10;
        }
        Serial.println("End Handling SDS011 query data");
        });

    if (!sds011.query_data_auto_async(pm_tablesize, pm25_table, pm10_table)) {
        Serial.println("measurement capture start failed");
    }

    deadline = millis() + duty_s * 1000;
    while (static_cast<int32_t>(deadline - millis()) > 0) {
        delay(1000);
        Serial.println(static_cast<int32_t>(deadline - millis()) / 1000);
        sds011.perform_work();
    }
}
/*
 * #######################################################
 */

//converts ascii char hex to values
char convertCharHexToValue(char ch)
{
  char res;
  int value = 30;
  if('0' <= ch && ch <= '9')
  {
    value = 48;
  }
  else
    if('A' <= ch && ch <= 'F')
    {
      value = 55;
    }else
      if('a' <= ch && ch <= 'f')
      {
        value = 87;
      }
  
  res = ch - value;
  return res;
}

// convert hex string to char array
void getHex(String text, char* buffer, int length)
{
  char tmp;
  int c=0;
  for(int i=0; i < text.length() && c <= length; i+=2)
  {
    tmp = (char)(convertCharHexToValue(text[i])<<4|convertCharHexToValue(text[i+1]));
    buffer[c++] = tmp;
  }
}

//convert char array (byte) to hex string
String toHexString(char* buffer, int length)
{
  String res = "";
  char tmp[2];
  for(int i=0; i < length; i++)
  {
    //res+=String(buffer[i], HEX);
    sprintf(tmp,"%02x",buffer[i]);
    res+=String(tmp);
  }
  return res;
}

String md5(String str) {
  MD5Builder _md5;
  _md5.begin();
  _md5.add(String(str));
  _md5.calculate();
  return _md5.toString();
}

void doEncrypt()
{
    unsigned long start;
    unsigned long elapsed;
    size_t clen;
    size_t plen;
    int res = 0;

    start = micros();
    res = ascon128_aead_encrypt(ciphertext, &clen,
     plaintext, strlen((const char*)plaintext),
     (const unsigned char*)associated, strlen((const char*)associated),
     (const unsigned char*)nonce,
     (const unsigned char*)key);
    Serial.print("res: ");
    Serial.println(res);
    Serial.print("clen: ");
    Serial.println(clen);
    Serial.println("encrypt:");
    size_t outputLength;
    unsigned char *encoded = base64_encode((const unsigned char *)ciphertext, clen, &outputLength);

    Serial.print("Length of encode message: ");
    Serial.println(outputLength);
    Serial.printf("%.*s", outputLength, encoded); 
    Serial.println(""); 
    encodedstr = String((const char*)encoded);

    sendData(encodedstr);
    
    Serial.println("======================");
    size_t decooutputLength;
    unsigned char * decoded = base64_decode((const unsigned char *)encoded, outputLength, &decooutputLength);   
    Serial.print("Length of decoded message: ");
    Serial.println(decooutputLength); 
    //Serial.printf("%.*s", decooutputLength, decoded);
    Serial.println(""); 
        res = ascon128_aead_decrypt(plaintext, &plen, decoded, decooutputLength,  
     (const unsigned char*)associated, strlen((const char*)associated),
     (const unsigned char*)nonce,
     (const unsigned char*)key);    
    Serial.print("res: ");
    Serial.println(res);
    Serial.print("plen: ");
    Serial.println(plen);
    Serial.print("decrypt:");
    Serial.println((char*)plaintext);
    Serial.println("======================");
    
    elapsed = micros() - start;
    Serial.print("elapsed: ");
    Serial.println(elapsed*0.001f);

    free(encoded);
    free(decoded);
}

void testString()
{
    //String stringOne = "1234567890|1234567890|1234567890|1234567890|1234567890|1234567890|1234567890|1234567890|1234567890|1234567890|1234567890|123456";
    String stringOne = "{\"widget\":{\"debug\":\"on\",\"window\":{\"title\":\"Sample Konfabulator Widget\",\"name\":\"main_window\",\"width\":500,\"height\":500},\"image\":{\"src\":\"Images/Sun.png\",\"name\":\"sun1\",\"hOffset\":250,\"vOffset\":250,\"alignment\":\"center\"},\"text\":{\"data\":\"Click Here\",\"size\":36,\"style\":\"bold\",\"name\":\"text1\",\"hOffset\":250,\"vOffset\":100,\"alignment\":\"center\",\"onMouseUp\":\"sun1.opacity = (sun1.opacity / 100) * 90;\"}}}";
    Serial.println(stringOne);
    Serial.println(stringOne.length());
    stringOne.toCharArray((char*)plaintext, MAX_DATA_SIZE);
    doEncrypt();
}


/*
 * #######################################################
 */

 
/**
 * Task: monitor the WiFi connection and keep it alive!
 * 
 * When a WiFi connection is established, this task will check it every 10 seconds 
 * to make sure it's still alive.
 * 
 * If not, a reconnect is attempted. If this fails to finish within the timeout,
 * the ESP32 will wait for it to recover and try again.
 */
void keepWiFiAlive(void * parameter){
    for(;;){
        Serial.print("CONNECTED:");
        Serial.println(connectState);
        if(WiFi.status() == WL_CONNECTED){
          Serial.println("Wifi still connected");
          getLocalTime();
          Serial.println(timeStamp);
          connectState = true;
          Serial.println();
            vTaskDelay(10000 / portTICK_PERIOD_MS);
            continue;
        }

        Serial.println("[WIFI] Connecting");
        WiFi.mode(WIFI_STA);
        WiFi.begin(WIFI_NETWORK, WIFI_PASSWORD);
        connectState = false;
        unsigned long startAttemptTime = millis();

        Serial.println("[WIFI] Connecting before while");
        // Keep looping while we're not connected and haven't reached the timeout
        while (WiFi.status() != WL_CONNECTED && 
                millis() - startAttemptTime < WIFI_TIMEOUT_MS){
                  Serial.print(".");
                  delay(100);
                  
         }
      Serial.print(" portTICK_PERIOD_MS: " );
      Serial.println(portTICK_PERIOD_MS);
      Serial.print("------------------" );
        // When we couldn't make a WiFi connection (or the timeout expired)
      // sleep for a while and then retry.
        if(WiFi.status() != WL_CONNECTED){
            Serial.println("[WIFI] FAILED");
            vTaskDelay(WIFI_RECOVER_TIME_MS / portTICK_PERIOD_MS);
            //vTaskDelay( 20000 );
            continue;
        }

        connectState = true;
        Serial.println("[WIFI] Connected: ");              
        ip_address = WiFi.localIP().toString();
        mac_address = WiFi.macAddress();
        mac_address.replace(":", ""); 
        Serial.print("IP: ");       
        Serial.println(ip_address);
        Serial.print("MAC: ");
        Serial.println(mac_address);
        numconnections++;
        mac_address.toCharArray((char*)associated, 33);
        // Init and get the time
        configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
        getLocalTime();
        Serial.println(timeStamp);
        Serial.println();
        getNonce();
    }
}

void getNonce()
{
  HTTPClient http;   
  Serial.println("################# REGSTRY ##############");
  http.begin(endpoint+"/register/");  //Specify destination for HTTP request
  http.addHeader("Content-Type", "application/json");             //Specify content-type header
  DynamicJsonDocument ddoc(256);
  String jsondata = "";
  //{"device":"661122334455", "key":"IOT-Key-202107lwc", "assoc":"test device"}
  ddoc["device"] = mac_address;
  ddoc["key"] = "IOT-Key-202107lwc";
  ddoc["assoc"] = associated;
  size_t len = serializeJson(ddoc, jsondata);
  
  int httpResponseCode = http.POST(jsondata);   //Send the actual POST request
  
  if(httpResponseCode>0){  
    String response = http.getString();                       //Get the response to the request
    
    Serial.println(httpResponseCode);   //Print return code
    Serial.println(response);           //Print request answer
  
    DynamicJsonDocument resdoc(1024);
    deserializeJson(resdoc, response);
    String strnonce = resdoc["nonce"];
    getHex(strnonce, (char*)nonce, 16);
    Serial.print("NONCE: ");
    Serial.println((char*)nonce);
    Serial.println(toHexString((char*)nonce, 16));
  
  }else{  
    Serial.print("Error on sending POST: ");
    Serial.println(httpResponseCode);  
  }  
  Serial.println("##############################################");
  http.end();  //Free resources  
}

void sendData(String strdata)
{
  HTTPClient http;   
  Serial.println("################# SENDING ##############");
  http.begin(endpoint+"/setDataDevice/");  //Specify destination for HTTP request
  http.addHeader("Content-Type", "application/json");             //Specify content-type header
  DynamicJsonDocument ddoc(1024);
  String jsondata = "";
  //{"device":"2462ABFCA4CC", "data":"UQB6uyKU6iWqZbOfniSkqd124keSYlRP/9ZALeHqHkLFmAYBX4fiS98MMzf9Ju+YJS8DmXNt\nwZCs4ng6W7Yop5AGSkb36ZLKFVXuUOGsgJU+iih9G0tkCK+Rjv4luojTc6HNA6hj30o/bgJB\nCtjtyQfzN6u0IFrjpiODKTjQZzkWt6e8P90EV9sRzW6ljw4AbCY9v/bfBJ+aqH6tPGT9Dv51\nGgzaqdE="}
  ddoc["device"] = mac_address;
  ddoc["data"] = strdata;
  Serial.println(strdata);  
  size_t len = serializeJson(ddoc, jsondata);
  Serial.println(jsondata);
  
  int httpResponseCode = http.POST(jsondata);   //Send the actual POST request
  
  if(httpResponseCode>0){  
    String response = http.getString();                       //Get the response to the request
    
    Serial.println(httpResponseCode);   //Print return code
    Serial.println(response);           //Print request answer
  
  }else{  
    Serial.print("Error on sending POST: ");
    Serial.println(httpResponseCode);  
  }  
  Serial.println("##############################################");
  http.end();  //Free resources  
}


void getLocalTime(){
  struct tm timeinfo;
  if(!getLocalTime(&timeinfo)){
    Serial.println("Failed to obtain time");
    return;
  }
  strftime(timeStamp,20, "%Y-%m-%d %H:%M:%S", &timeinfo);  
}


// SENSOR PART
// https://github.com/miguel5612/MQSensorsLib_Docs/blob/master/static/img/MQ_ESP8266.PNG
//Include the library
#include "MQUnifiedsensor.h"
/************************Hardware Related Macros************************************/
#define         Board                   ("ESP-32") // Wemos ESP-32 or other board, whatever have ESP32 core.
#define         Pin                     (36)  
/***********************Software Related Macros************************************/
#define         Type                    ("MQ-135") //MQ135 or other MQ Sensor, if change this verify your a and b values.
#define         Voltage_Resolution      (3.3) // 3V3 <- IMPORTANT. Source: https://randomnerdtutorials.com/esp32-adc-analog-read-arduino-ide/
#define         ADC_Bit_Resolution      (12) // ESP-32 bit resolution. Source: https://randomnerdtutorials.com/esp32-adc-analog-read-arduino-ide/
#define         RatioMQ135CleanAir      (3.6) //RS / R0 = 3.6 ppm  
#define         ReadMqinterval          (300000) //read interval

//Declare Sensor
MQUnifiedsensor MQ135(Board, Voltage_Resolution, ADC_Bit_Resolution, Pin, Type);

unsigned int nextcycle = 0;

void getSensorValue(void * parameter){
  StaticJsonDocument<1024> doc;
  for(;;){
    if(connectState)
    {
      doc.clear();
      JsonObject root = doc.to<JsonObject>();
      
      root["IP"] = ip_address;
      root["MAC"] = mac_address;
      getLocalTime();
      root["time"] = timeStamp;

      JsonObject sensor = root.createNestedObject("sensor");
      JsonArray datamq135 = sensor.createNestedArray("MQ-135"); 
      JsonArray datasds011 = sensor.createNestedArray("SDS011");

      doMeasure();
      datasds011.add(mpm10);
      datasds011.add(mpm25);   
       
      MQ135.update(); // Update data, the arduino will be read the voltage on the analog pin
    
      MQ135.setA(605.18); MQ135.setB(-3.937); // Configurate the ecuation values to get CO concentration
      float CO = MQ135.readSensor(); // Sensor will read PPM concentration using the model and a and b values setted before or in the setup
      datamq135.add(CO);
    
      MQ135.setA(77.255); MQ135.setB(-3.18); // Configurate the ecuation values to get Alcohol concentration
      float Alcohol = MQ135.readSensor(); // Sensor will read PPM concentration using the model and a and b values setted before or in the setup
      datamq135.add(Alcohol);
    
      MQ135.setA(110.47); MQ135.setB(-2.862); // Configurate the ecuation values to get CO2 concentration
      float CO2 = MQ135.readSensor(); // Sensor will read PPM concentration using the model and a and b values setted before or in the setup
      datamq135.add(CO2);
    
      MQ135.setA(44.947); MQ135.setB(-3.445); // Configurate the ecuation values to get Tolueno concentration
      float Tolueno = MQ135.readSensor(); // Sensor will read PPM concentration using the model and a and b values setted before or in the setup
      datamq135.add(Tolueno);
    
      MQ135.setA(102.2 ); MQ135.setB(-2.473); // Configurate the ecuation values to get NH4 concentration
      float NH4 = MQ135.readSensor(); // Sensor will read PPM concentration using the model and a and b values setted before or in the setup
      datamq135.add(NH4);
    
      MQ135.setA(34.668); MQ135.setB(-3.369); // Configurate the ecuation values to get Acetona concentration
      float Acetona = MQ135.readSensor(); // Sensor will read PPM concentration using the model and a and b values setted before or in the setup
      datamq135.add(Acetona);
  
      if(nextcycle == 0)
      {
        MQ135.serialDebug();
        Serial.println("** Lectures from MQ-135 ****");
        Serial.println("|    CO   |  Alcohol |   CO2  |  Tolueno  |  NH4  |  Acteona  |");      
      }
      nextcycle++;
      if(nextcycle==11) nextcycle=0;
    
      Serial.print("|   "); Serial.print(CO); 
      Serial.print("   |   "); Serial.print(Alcohol);
      // Note: 200 Offset for CO2 source: https://github.com/miguel5612/MQSensorsLib/issues/29
      /*
      Motivation:
      We have added 200 PPM because when the library is calibrated it assumes the current state of the
      air as 0 PPM, and it is considered today that the CO2 present in the atmosphere is around 400 PPM.
      https://www.lavanguardia.com/natural/20190514/462242832581/concentracion-dioxido-cabono-co2-atmosfera-bate-record-historia-humanidad.html
      */
      Serial.print("   |   "); Serial.print(CO2 + 400); 
      Serial.print("   |   "); Serial.print(Tolueno); 
      Serial.print("   |   "); Serial.print(NH4); 
      Serial.print("   |   "); Serial.print(Acetona);
      Serial.println("   |"); 
      Serial.println(""); 
      serializeJson(doc, Serial);
      Serial.println("");
      size_t sdata = serializeJson(doc, (char*)plaintext, MAX_DATA_SIZE);
      Serial.print("Serialize data size:");
      Serial.println(sdata);
      Serial.print("Serialize data:");
      Serial.println((char*)plaintext);
      doEncrypt();
      
      /*
        Exponential regression:
      GAS      | a      | b
      CO       | 605.18 | -3.937  
      Alcohol  | 77.255 | -3.18 
      CO2      | 110.47 | -2.862
      Tolueno  | 44.947 | -3.445
      NH4      | 102.2  | -2.473
      Acetona  | 34.668 | -3.369
      */
      }
      vTaskDelay(ReadMqinterval / portTICK_PERIOD_MS);    
  }
}

void setup() {
  Serial.begin(115200);

#ifdef ESP32
    serialSDS.begin(9600, SERIAL_8N1, SDS_PIN_RX, SDS_PIN_TX);
    delay(100);
#endif

    Serial.println("SDS011 start/stop and reporting sample");
    start_SDS();
    
    String firmware_version;
    uint16_t device_id;
    if (!sds011.device_info(firmware_version, device_id)) {
        Serial.println("Sds011::firmware_version() failed");
    }
    else
    {
        Serial.print("Sds011 firmware version: ");
        Serial.println(firmware_version);
        Serial.print("Sds011 device id: ");
        Serial.println(device_id, 16);
    }

    Sds011::Report_mode report_mode;
    if (!sds011.get_data_reporting_mode(report_mode)) {
        Serial.println("Sds011::get_data_reporting_mode() failed");
    }
    if (Sds011::REPORT_ACTIVE != report_mode) {
        Serial.println("Turning on Sds011::REPORT_ACTIVE reporting mode");
        if (!sds011.set_data_reporting_mode(Sds011::REPORT_ACTIVE)) {
            Serial.println("Sds011::set_data_reporting_mode(Sds011::REPORT_ACTIVE) failed");
        }
    }

  Serial.println();
  
  //Set math model to calculate the PPM concentration and the value of constants
  MQ135.setRegressionMethod(1); //_PPM =  a*ratio^b
  
  /*****************************  MQ Init ********************************************/ 
  //Remarks: Configure the pin of arduino as input.
  /************************************************************************************/ 
  MQ135.init(); 
  /* 
    //If the RL value is different from 10K please assign your RL value with the following method:
    MQ135.setRL(10);
  */
  /*****************************  MQ CAlibration ********************************************/ 
  // Explanation: 
  // In this routine the sensor will measure the resistance of the sensor supposing before was pre-heated
  // and now is on clean air (Calibration conditions), and it will setup R0 value.
  // We recomend execute this routine only on setup or on the laboratory and save on the eeprom of your arduino
  // This routine not need to execute to every restart, you can load your R0 if you know the value
  // Acknowledgements: https://jayconsystems.com/blog/understanding-a-gas-sensor
  Serial.print("Calibrating please wait.");
  float calcR0 = 0;
  for(int i = 1; i<=10; i ++)
  {
    MQ135.update(); // Update data, the arduino will be read the voltage on the analog pin
    calcR0 += MQ135.calibrate(RatioMQ135CleanAir);
    Serial.print(".");
  }
  MQ135.setR0(calcR0/10);
  Serial.println("  done!.");
  
  if(isinf(calcR0)) {Serial.println("Warning: Conection issue founded, R0 is infite (Open circuit detected) please check your wiring and supply"); while(1);}
  if(calcR0 == 0){Serial.println("Warning: Conection issue founded, R0 is zero (Analog pin with short circuit to ground) please check your wiring and supply"); while(1);}
  /*****************************  MQ CAlibration ********************************************/ 
  
  MQ135.serialDebug(true);
  
  xTaskCreatePinnedToCore(
  keepWiFiAlive,
  "keepWiFiAlive",  // Task name
  5000,             // Stack size (bytes)
  NULL,             // Parameter
  1,                // Task priority
  NULL,             // Task handle
  CONFIG_ARDUINO_RUNNING_CORE
  );

  xTaskCreatePinnedToCore(
  getSensorValue,
  "getSensorValue",  // Task name
  5000,             // Stack size (bytes)
  NULL,             // Parameter
  1,                // Task priority
  NULL,             // Task handle
  CONFIG_ARDUINO_RUNNING_CORE
  );
}

void loop() {
  // put your main code here, to run repeatedly:

}

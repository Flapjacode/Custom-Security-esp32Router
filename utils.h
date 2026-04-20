/*
 * utils.h
 * Logging macros using Serial. Tag-based severity levels.
 */
#pragma once
#include <Arduino.h>

#define LOG_I(fmt, ...) do { Serial.printf("[INFO] " fmt "\r\n", ##__VA_ARGS__); } while(0)
#define LOG_W(fmt, ...) do { Serial.printf("[WARN] " fmt "\r\n", ##__VA_ARGS__); } while(0)
#define LOG_E(fmt, ...) do { Serial.printf("[ERR ] " fmt "\r\n", ##__VA_ARGS__); } while(0)

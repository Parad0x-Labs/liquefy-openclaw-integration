#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Simple Varint Encoder in C
int pack_varint(uint32_t val, uint8_t* out) {
    int len = 0;
    while (val >= 0x80) {
        out[len++] = (val & 0x7F) | 0x80;
        val >>= 7;
    }
    out[len++] = val;
    return len;
}

// SQL Titan Transform
// Directly builds the Template and Variable streams in one pass.
int32_t transform_sql(const uint8_t* data, uint32_t data_len,
                      uint8_t* tpl_out, uint32_t* tpl_len,
                      uint8_t* var_out, uint32_t* var_len,
                      uint32_t* var_count) {
    uint32_t pos = 0;
    uint32_t last_pos = 0;
    uint32_t v_ptr = 0;
    uint32_t t_ptr = 0;
    uint32_t v_count = 0;

    while (pos < data_len) {
        uint8_t c = data[pos];
        uint32_t v_start = 0;
        uint32_t v_l = 0;

        if (c == '\'' || c == '"' || c == '`') {
            uint8_t quote = c; v_start = pos; pos++;
            while (pos < data_len) {
                if (data[pos] == '\\' && pos + 1 < data_len) { pos += 2; continue; }
                if (data[pos] == quote) { pos++; break; }
                pos++;
            }
            v_l = pos - v_start;
        } else if (c >= '0' && c <= '9' || (c == '-' && pos + 1 < data_len && data[pos+1] >= '0' && data[pos+1] <= '9')) {
            v_start = pos; pos++;
            while (pos < data_len && ((data[pos] >= '0' && data[pos] <= '9') || data[pos] == '.')) pos++;
            v_l = pos - v_start;
        } else {
            pos++; continue;
        }

        // Template logic
        if (v_start > last_pos) {
            memcpy(&tpl_out[t_ptr], &data[last_pos], v_start - last_pos);
            t_ptr += (v_start - last_pos);
        }
        tpl_out[t_ptr++] = 0; // Null placeholder

        // Variable logic
        v_ptr += pack_varint(v_l, &var_out[v_ptr]);
        memcpy(&var_out[v_ptr], &data[v_start], v_l);
        v_ptr += v_l;
        v_count++;
        last_pos = pos;
    }

    if (last_pos < data_len) {
        memcpy(&tpl_out[t_ptr], &data[last_pos], data_len - last_pos);
        t_ptr += (data_len - last_pos);
    }

    *tpl_len = t_ptr;
    *var_len = v_ptr;
    *var_count = v_count;
    return 0;
}

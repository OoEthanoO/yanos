#define NULL ((void*)0)

static inline unsigned char inportb(unsigned short port) {
    unsigned char ret;
    asm volatile ( "inb %1, %0"
                   : "=a"(ret)
                   : "Nd"(port) );
    return ret;
}

static inline void outportb(unsigned short port, unsigned char data) {
    asm volatile ( "outb %0, %1" : : "a"(data), "Nd"(port) );
}

static inline unsigned short inportw(unsigned short port) {
    unsigned short ret;
    asm volatile ( "inw %1, %0"
                   : "=a"(ret)
                   : "Nd"(port) );
    return ret;
}

#define ATA_PRIMARY_DATA         0x1F0
#define ATA_PRIMARY_ERROR        0x1F1
#define ATA_PRIMARY_SECTOR_COUNT 0x1F2
#define ATA_PRIMARY_LBA_LOW      0x1F3
#define ATA_PRIMARY_LBA_MID      0x1F4
#define ATA_PRIMARY_LBA_HIGH     0x1F5
#define ATA_PRIMARY_DRIVE_HEAD   0x1F6
#define ATA_PRIMARY_COMMAND      0x1F7
#define ATA_PRIMARY_STATUS       0x1F7

#define ATA_CMD_READ_SECTORS  0x20
#define ATA_CMD_WRITE_SECTORS 0x30
#define ATA_CMD_CACHE_FLUSH   0xE7
#define ATA_CMD_IDENTIFY      0xEC

#define ATA_SR_BSY  0x80
#define ATA_SR_DRDY 0x40
#define ATA_SR_DF   0x20
#define ATA_SR_DSC  0x10
#define ATA_SR_DRQ  0x08
#define ATA_SR_CORR 0x04
#define ATA_SR_IDX  0x02
#define ATA_SR_ERR  0x01

static void ata_wait_bsy_clear(void) {
    while (inportb(ATA_PRIMARY_STATUS) & ATA_SR_BSY) {
    }
}

static void ata_wait_drq_set(void) {
    while (!(inportb(ATA_PRIMARY_STATUS) & ATA_SR_DRQ)) {
        if (inportb(ATA_PRIMARY_STATUS) & ATA_SR_ERR) {
            return;
        }
    }
}

static int read_disk_sector(unsigned int lba, unsigned char* buffer) {
    ata_wait_bsy_clear();
    while (!(inportb(ATA_PRIMARY_STATUS) & ATA_SR_DRDY)) {
        if (inportb(ATA_PRIMARY_STATUS) & ATA_SR_ERR) return 1;
    }

    outportb(ATA_PRIMARY_DRIVE_HEAD, 0xE0 | ((lba >> 24) & 0x0F));

    outportb(ATA_PRIMARY_SECTOR_COUNT, 1);

    outportb(ATA_PRIMARY_LBA_LOW, (unsigned char)(lba & 0xFF));

    outportb(ATA_PRIMARY_LBA_MID, (unsigned char)((lba >> 8) & 0xFF));

    outportb(ATA_PRIMARY_LBA_HIGH, (unsigned char)((lba >> 16) & 0xFF));

    outportb(ATA_PRIMARY_COMMAND, ATA_CMD_READ_SECTORS);

    ata_wait_drq_set();
    if (inportb(ATA_PRIMARY_STATUS) & ATA_SR_ERR) {
        return 1;
    }

    for (int i = 0; i < 256; i++) {
        unsigned short data_word = inportw(ATA_PRIMARY_DATA);
        buffer[i * 2] = (unsigned char)(data_word & 0xFF);
        buffer[i * 2 + 1] = (unsigned char)((data_word >> 8) & 0xFF);
    }
    return 0;
}

static void update_cursor(unsigned int screen_offset) {
    unsigned short position = screen_offset / 2;

    outportb(0x3D4, 0x0E);
    outportb(0x3D5, (unsigned char)((position >> 8) & 0xFF));
    outportb(0x3D4, 0x0F);
    outportb(0x3D5, (unsigned char)(position & 0xFF));
}

unsigned char read_scancode(void) {
    unsigned char scancode;
    while ((inportb(0x64) & 0x01) == 0) {
    }
    scancode = inportb(0x60);
    return scancode;
}

static const char scancode_map[] = {
    0,  0x1B, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    0,
    0, ' '
};

#define KEY_LEFT_ARROW 0x01
#define KEY_RIGHT_ARROW 0x02

static char scancode_to_ascii(unsigned char scancode) {
    if (scancode == 0x4B) return KEY_LEFT_ARROW;
    if (scancode == 0x4D) return KEY_RIGHT_ARROW;

    if (scancode < sizeof(scancode_map)) {
        return scancode_map[scancode];
    }
    return 0;
}

static unsigned int strlen_simple(const char* s) {
    unsigned int len = 0;
    while (s[len]) {
        len++;
    }
    return len;
}

static int strcmp_simple(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

static int strncmp_simple(const char* s1, const char* s2, unsigned int n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) {
        return 0;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

#define MAX_COMMAND_LENGTH 80
#define OS_VERSION "YanOS v0.1.0"
#define OS_AUTHOR_INFO "Author: Ethan Yan Xu. A simple hobby OS."

struct File {
    char name[16];
    char content[128];
    int in_use;
};

#define MAX_FILES 10
struct File file_table[MAX_FILES];

static void strncpy_simple(char* dest, const char* src, unsigned int n) {
    unsigned int i;
    for (i = 0; i < n - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

static int fs_create_file(const char* filename) {
    if (strlen_simple(filename) >= sizeof(file_table[0].name)) {
        return 1;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, filename) == 0) {
            return 1;
        }
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 0) {
            strncpy_simple(file_table[i].name, filename, sizeof(file_table[i].name));
            file_table[i].in_use = 1;
            file_table[i].content[0] = '\0';
            return 0;
        }
    }
    return 1;
}

static int fs_write_file(const char* filename, const char* data) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, filename) == 0) {
            if (strlen_simple(data) < sizeof(file_table[i].content)) {
                strncpy_simple(file_table[i].content, data, sizeof(file_table[i].content));
                return 0;
            } else {
                return 1;
            }
        }
    }
    return 1;
}

static int fs_delete_file(const char* filename) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, filename) == 0) {
            file_table[i].in_use = 0;
            return 0;
        }
    }
    return 1;
}

static int fs_read_file(
    const char* filename,
    char* vidptr,
    unsigned int* cursor_pos_ptr,
    unsigned int screen_width_chars,
    unsigned int screen_total_bytes
) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, filename) == 0) {
            unsigned int content_idx = 0;
            while (file_table[i].content[content_idx] != '\0') {
                if (*cursor_pos_ptr >= screen_total_bytes - 2 && file_table[i].content[content_idx] != '\n') {
                    break;
                }

                if (file_table[i].content[content_idx] == '\n') {
                    unsigned int current_row_for_newline = (*cursor_pos_ptr / 2) / screen_width_chars;
                    *cursor_pos_ptr = (current_row_for_newline + 1) * screen_width_chars * 2;
                    if (*cursor_pos_ptr >= screen_total_bytes) {
                        break;
                    }
                } else {
                    vidptr[*cursor_pos_ptr] = file_table[i].content[content_idx];
                    vidptr[*cursor_pos_ptr + 1] = 0x07;
                    *cursor_pos_ptr += 2;
                }
                content_idx++;
            }
            return 0;
        }
    }
    return 1;
}

static void fs_list_files(
    char* vidptr,
    unsigned int* cursor_pos_ptr,
    unsigned int screen_width_chars,
    unsigned int screen_height_chars,
    unsigned int screen_total_bytes
) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1) {
            unsigned int name_idx = 0;
            while (file_table[i].name[name_idx] != '\0' && *cursor_pos_ptr < screen_total_bytes - 2) {
                vidptr[*cursor_pos_ptr] = file_table[i].name[name_idx];
                vidptr[*cursor_pos_ptr + 1] = 0x07;
                *cursor_pos_ptr += 2;
                name_idx++;
            }

            unsigned int current_row = (*cursor_pos_ptr / 2) / screen_width_chars;
            
            *cursor_pos_ptr = (current_row + 1) * screen_width_chars * 2;

            if (*cursor_pos_ptr >= screen_total_bytes) {
                *cursor_pos_ptr = (screen_height_chars - 1) * screen_width_chars * 2;
            }
        }
    }
}

static void fs_init(void) {
    for (int i = 0; i < MAX_FILES; i++) {
        file_table[i].in_use = 0;
    }
}

void kmain(void) {
    const char *prompt_display_str = "> ";
    char *vidptr = (char*)0xb8000;
    unsigned int loop_idx;

    unsigned int cursor_pos = 0;
    unsigned int current_line_input_start_offset = 0;

    const unsigned int screen_width_chars = 80;
    const unsigned int screen_height_chars = 25;
    const unsigned int screen_total_bytes = screen_width_chars * screen_height_chars * 2;
    const unsigned int prompt_len_chars = strlen_simple(prompt_display_str);
    const unsigned int prompt_len_bytes = prompt_len_chars * 2;

    char command_buffer[MAX_COMMAND_LENGTH];
    unsigned int command_length = 0;
    unsigned int command_cursor_logical_idx = 0;

    for (loop_idx = 0; loop_idx < screen_total_bytes; loop_idx += 2) {
        vidptr[loop_idx] = ' ';
        vidptr[loop_idx+1] = 0x07;
    }

    const char *os_display_name = "YanOS";
    unsigned int display_name_char_idx = 0;
    while(os_display_name[display_name_char_idx] != '\0' && cursor_pos < screen_total_bytes) {
        vidptr[cursor_pos] = os_display_name[display_name_char_idx];
        vidptr[cursor_pos+1] = 0x07;
        cursor_pos += 2;
        display_name_char_idx++;
    }

    if (cursor_pos < screen_total_bytes) {
        unsigned int current_row = (cursor_pos / 2) / screen_width_chars;
        cursor_pos = (current_row + 1) * screen_width_chars * 2;
        if (cursor_pos >= screen_total_bytes) {
            cursor_pos = (screen_height_chars -1) * screen_width_chars * 2;
        }
    }
    update_cursor(cursor_pos);
    
    fs_init();

    while(1) {
        unsigned int prompt_start_row = (cursor_pos / 2) / screen_width_chars;
        unsigned int prompt_start_col_bytes = cursor_pos % (screen_width_chars * 2);

        if (prompt_start_row >= screen_height_chars ||
            (prompt_start_row == screen_height_chars - 1 && prompt_start_col_bytes + prompt_len_bytes > screen_width_chars * 2)) {
            for (loop_idx = 0; loop_idx < screen_total_bytes; loop_idx += 2) {
                vidptr[loop_idx] = ' '; vidptr[loop_idx+1] = 0x07;
            }
            cursor_pos = 0;
        }

        unsigned int current_char_idx = 0;
        unsigned int prompt_char_print_pos = cursor_pos;
        while(prompt_display_str[current_char_idx] != '\0') {
            if (prompt_char_print_pos < screen_total_bytes) {
                 vidptr[prompt_char_print_pos] = prompt_display_str[current_char_idx];
                 vidptr[prompt_char_print_pos+1] = 0x07;
                 prompt_char_print_pos += 2;
            } else { break; }
            current_char_idx++;
        }
        current_line_input_start_offset = prompt_char_print_pos;
        cursor_pos = current_line_input_start_offset;
        update_cursor(cursor_pos);

        command_length = 0;
        command_cursor_logical_idx = 0;

        while(1) {
            unsigned char scancode = read_scancode();
            char pressed_char = scancode_to_ascii(scancode);

            if (pressed_char != 0) {
                if (pressed_char == '\n') {
                    command_buffer[command_length] = '\0';

                    unsigned int current_row = (cursor_pos / 2) / screen_width_chars;
                    cursor_pos = (current_row + 1) * screen_width_chars * 2;
                    
                    if (cursor_pos >= screen_total_bytes) {
                    }

                    int command_found = 0;
                    if (strcmp_simple(command_buffer, "help") == 0) {
                        command_found = 1;
                        const char* help_msg = "Available commands: help, cls, mkfile <filename>, ls, write <filename> <content>, read <filename>, rm <filename>, version";
                        unsigned int k = 0;
                        if (cursor_pos < screen_total_bytes) { 
                            while(help_msg[k] != '\0' && cursor_pos < screen_total_bytes) {
                                vidptr[cursor_pos] = help_msg[k];
                                vidptr[cursor_pos+1] = 0x07;
                                cursor_pos += 2;
                                k++;
                            }
                        }
                    } else if (strcmp_simple(command_buffer, "cls") == 0) {
                        command_found = 1;
                        for (loop_idx = 0; loop_idx < screen_total_bytes; loop_idx += 2) {
                            vidptr[loop_idx] = ' ';
                            vidptr[loop_idx+1] = 0x07;
                        }
                        cursor_pos = 0;
                        
                        const char *os_display_name = "YanOS";
                        unsigned int display_name_char_idx = 0;
                        while(os_display_name[display_name_char_idx] != '\0' && cursor_pos < screen_total_bytes) {
                            vidptr[cursor_pos] = os_display_name[display_name_char_idx];
                            vidptr[cursor_pos+1] = 0x07;
                            cursor_pos += 2;
                            display_name_char_idx++;
                        }

                        update_cursor(cursor_pos);
                    } else if (strncmp_simple(command_buffer, "mkfile ", 7) == 0) {
                        command_found = 1;
                        const char* filename_to_create = command_buffer + 7;
                        const char* msg;
                        if (strlen_simple(filename_to_create) > 0) {
                            if (fs_create_file(filename_to_create) == 0) {
                                msg = "File created.";
                            } else {
                                msg = "Error creating file (full or invalid name).";
                            }
                        } else {
                            msg = "Usage: mkfile <filename>";
                        }
                        unsigned int k = 0;
                        if (cursor_pos < screen_total_bytes) {
                            while(msg[k] != '\0' && cursor_pos < screen_total_bytes) {
                                vidptr[cursor_pos] = msg[k];
                                vidptr[cursor_pos+1] = 0x07;
                                cursor_pos += 2;
                                k++;
                            }
                        }
                    } else if (strcmp_simple(command_buffer, "ls") == 0) {
                        command_found = 1;
                        fs_list_files(vidptr, &cursor_pos, screen_width_chars, screen_height_chars, screen_total_bytes);
                    } else if (strncmp_simple(command_buffer, "write ", 6) == 0) {
                        command_found = 1;
                        char filename_arg[sizeof(file_table[0].name)];
                        char content_arg[sizeof(file_table[0].content)];
                        const char* p = command_buffer + 6;
                        unsigned int i = 0;
                        const char* msg;

                        while (*p != ' ' && *p != '\0' && i < sizeof(filename_arg) - 1) {
                            filename_arg[i++] = *p++;
                        }
                        filename_arg[i] = '\0';

                        if (*p == ' ') p++;

                        i = 0;
                        while (*p != '\0' && i < sizeof(content_arg) - 1) {
                            content_arg[i++] = *p++;
                        }
                        content_arg[i] = '\0';

                        if (strlen_simple(filename_arg) > 0 && strlen_simple(content_arg) > 0) {
                            if (fs_write_file(filename_arg, content_arg) == 0) {
                                msg = "File written.";
                            } else {
                                msg = "Error writing file (not found or content too large).";
                            }
                        } else {
                            msg = "Usage: write <filename> <content>";
                        }

                        unsigned int k = 0;
                        if (cursor_pos < screen_total_bytes) {
                            while(msg[k] != '\0' && cursor_pos < screen_total_bytes) {
                                vidptr[cursor_pos] = msg[k];
                                vidptr[cursor_pos+1] = 0x07;
                                cursor_pos += 2;
                                k++;
                            }
                        }
                    } else if (strncmp_simple(command_buffer, "read ", 5) == 0) {
                        command_found = 1;
                        const char* filename_to_read = command_buffer + 5;
                        const char* msg = NULL;

                        if (strlen_simple(filename_to_read) > 0) {
                            if (fs_read_file(filename_to_read, vidptr, &cursor_pos, screen_width_chars, screen_total_bytes) != 0) {
                                msg = "Error: File not found.";
                            }
                        } else {
                            msg = "Usage: read <filename>";
                        }

                        if (msg) {
                            unsigned int k = 0;
                            if (cursor_pos < screen_total_bytes) {
                                while(msg[k] != '\0' && cursor_pos < screen_total_bytes - 2) {
                                    vidptr[cursor_pos] = msg[k];
                                    vidptr[cursor_pos+1] = 0x07;
                                    cursor_pos += 2;
                                    k++;
                                }
                            }
                        }
                    } else if (strncmp_simple(command_buffer, "rm ", 3) == 0) {
                        command_found = 1;
                        const char* filename_to_delete = command_buffer + 3;
                        const char* msg;
                        if (strlen_simple(filename_to_delete) > 0) {
                            if (fs_delete_file(filename_to_delete) == 0) {
                                msg = "File deleted.";
                            } else {
                                msg = "Error deleting file (not found).";
                            }
                        } else {
                            msg = "Usage: rm <filename>";
                        }
                        unsigned int k = 0;
                        if (cursor_pos < screen_total_bytes) {
                            while(msg[k] != '\0' && cursor_pos < screen_total_bytes - 2) {
                                vidptr[cursor_pos] = msg[k];
                                vidptr[cursor_pos+1] = 0x07;
                                cursor_pos += 2;
                                k++;
                            }
                        }
                    } else if (strncmp_simple(command_buffer, "read ", 5) == 0) {
                        command_found = 1;
                        const char* filename_to_read = command_buffer + 5;
                        const char* msg = NULL;

                        if (strlen_simple(filename_to_read) > 0) {
                            if (fs_read_file(filename_to_read, vidptr, &cursor_pos, screen_width_chars, screen_total_bytes) != 0) {
                                msg = "Error: File not found.";
                            }
                        } else {
                            msg = "Usage: read <filename>";
                        }

                        if (msg) {
                            unsigned int k = 0;
                            if (cursor_pos < screen_total_bytes) {
                                while(msg[k] != '\0' && cursor_pos < screen_total_bytes - 2) {
                                    vidptr[cursor_pos] = msg[k];
                                    vidptr[cursor_pos+1] = 0x07;
                                    cursor_pos += 2;
                                    k++;
                                }
                            }
                        }
                    } else if (strcmp_simple(command_buffer, "version") == 0) {
                        command_found = 1;
                        unsigned int k = 0;
                        if (cursor_pos < screen_total_bytes) {
                            while(OS_VERSION[k] != '\0' && cursor_pos < screen_total_bytes - 2) {
                                vidptr[cursor_pos] = OS_VERSION[k];
                                vidptr[cursor_pos+1] = 0x07;
                                cursor_pos += 2;
                                k++;
                            }
                            unsigned int current_row = (cursor_pos / 2) / screen_width_chars;
                            cursor_pos = (current_row + 1) * screen_width_chars * 2;
                            if (cursor_pos >= screen_total_bytes) {
                            } else {
                                k = 0;
                                while(OS_AUTHOR_INFO[k] != '\0' && cursor_pos < screen_total_bytes - 2) {
                                    vidptr[cursor_pos] = OS_AUTHOR_INFO[k];
                                    vidptr[cursor_pos+1] = 0x07;
                                    cursor_pos += 2;
                                    k++;
                                }
                            }
                        }
                    }
                    
                    if (!command_found && command_length > 0) {
                        const char* unknown_cmd_msg = "Unknown command";
                        unsigned int k = 0;
                        if (cursor_pos < screen_total_bytes) {
                            while(unknown_cmd_msg[k] != '\0' && cursor_pos < screen_total_bytes) {
                                vidptr[cursor_pos] = unknown_cmd_msg[k];
                                vidptr[cursor_pos+1] = 0x07;
                                cursor_pos += 2;
                                k++;
                            }
                        }
                    }

                    current_row = (cursor_pos / 2) / screen_width_chars;
                    if ((cursor_pos / 2) % screen_width_chars != 0 || command_length > 0 || command_found) {
                        cursor_pos = (current_row + 1) * screen_width_chars * 2;
                    }
                    
                    command_length = 0;
                    command_cursor_logical_idx = 0;
                    break; 

                } else if (pressed_char == '\b') {
                    if (command_cursor_logical_idx > 0 && command_length > 0) {
                        for (unsigned int i = command_cursor_logical_idx - 1; i < command_length - 1; i++) {
                            command_buffer[i] = command_buffer[i+1];
                        }
                        command_length--;
                        command_cursor_logical_idx--;
                        command_buffer[command_length] = '\0';

                        cursor_pos = current_line_input_start_offset + command_cursor_logical_idx * 2;

                        unsigned int temp_screen_pos = cursor_pos;
                        for (unsigned int i = command_cursor_logical_idx; i < command_length; i++) {
                            vidptr[temp_screen_pos] = command_buffer[i];
                            vidptr[temp_screen_pos+1] = 0x07;
                            temp_screen_pos += 2;
                        }
                        vidptr[temp_screen_pos] = ' ';
                        vidptr[temp_screen_pos+1] = 0x07;
                    }
                } else if (pressed_char == KEY_LEFT_ARROW) {
                    if (command_cursor_logical_idx > 0) {
                        command_cursor_logical_idx--;
                        cursor_pos -= 2;
                    }
                } else if (pressed_char == KEY_RIGHT_ARROW) {
                    if (command_cursor_logical_idx < command_length) {
                        command_cursor_logical_idx++;
                        cursor_pos += 2;
                    }
                } else {
                    if (pressed_char >= ' ' && command_length < MAX_COMMAND_LENGTH - 1) {
                        unsigned int current_char_screen_pos = current_line_input_start_offset + command_cursor_logical_idx * 2;
                        if (current_char_screen_pos < (current_line_input_start_offset / (screen_width_chars*2) + 1) * screen_width_chars * 2 -2 &&
                            current_char_screen_pos < screen_total_bytes -2) {

                            for (unsigned int i = command_length; i > command_cursor_logical_idx; i--) {
                                command_buffer[i] = command_buffer[i-1];
                            }
                            command_buffer[command_cursor_logical_idx] = pressed_char;
                            command_length++;
                            command_buffer[command_length] = '\0';

                            unsigned int temp_screen_pos = current_char_screen_pos;
                            for (unsigned int i = command_cursor_logical_idx; i < command_length; i++) {
                                if (temp_screen_pos < screen_total_bytes - 2) {
                                    vidptr[temp_screen_pos] = command_buffer[i];
                                    vidptr[temp_screen_pos+1] = 0x07;
                                    temp_screen_pos += 2;
                                } else { break; }
                            }
                            command_cursor_logical_idx++;
                            cursor_pos = current_line_input_start_offset + command_cursor_logical_idx * 2;
                        }
                    }
                }
                update_cursor(cursor_pos);
            }
        }
    }
    return;
}
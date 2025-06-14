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

static inline void outportw(unsigned short port, unsigned short data) {
    asm volatile ( "outw %0, %1" : : "a"(data), "Nd"(port) );
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

#define FILE_TABLE_LBA 10001
#define SECTOR_BITMAP_LBA 10002
#define DATA_START_LBA 10003
#define NUM_DATA_SECTORS_MANAGED 4096
#define SECTOR_BITMAP_SIZE_BYTES (NUM_DATA_SECTORS_MANAGED / 8)

static unsigned char sector_bitmap[SECTOR_BITMAP_SIZE_BYTES];

static int write_disk_sector(unsigned int lba, const unsigned char* buffer);
static int read_disk_sector(unsigned int lba, unsigned char* buffer);
static void ata_wait_bsy_clear(void);
static void ata_wait_drq_set(void);

static int is_sector_used(unsigned int sector_index) {
    if (sector_index >= NUM_DATA_SECTORS_MANAGED) {
        return 0;
    }
    unsigned int byte_index = sector_index / 8;
    unsigned int bit_index = sector_index % 8;
    return (sector_bitmap[byte_index] & (1 << bit_index)) != 0;
}

static void set_sector_used(unsigned int sector_index) {
    if (sector_index >= NUM_DATA_SECTORS_MANAGED) {
        return;
    }
    unsigned int byte_index = sector_index / 8;
    unsigned int bit_index = sector_index % 8;
    sector_bitmap[byte_index] |= (1 << bit_index);
}

static void set_sector_free(unsigned int sector_index) {
    if (sector_index >= NUM_DATA_SECTORS_MANAGED) {
        return;
    }
    unsigned int byte_index = sector_index / 8;
    unsigned int bit_index = sector_index % 8;
    sector_bitmap[byte_index] &= ~(1 << bit_index);
}

static unsigned int allocate_disk_space(unsigned int num_bytes) {
    if (num_bytes == 0) {
        return 0;
    }

    unsigned int num_sectors_needed = (num_bytes + 511) / 512;

    if (num_sectors_needed == 0) {
        return 0;
    }
    if (num_sectors_needed > NUM_DATA_SECTORS_MANAGED) {
        return 0;
    }

    for (unsigned int i = 0; i < NUM_DATA_SECTORS_MANAGED - num_sectors_needed; ++i) {
        int block_is_free = 1;
        for (unsigned int j = 0; j < num_sectors_needed; ++j) {
            if (is_sector_used(i + j)) {
                block_is_free = 0;
                break;
            }
        }

        if (block_is_free) {
            for (unsigned int j = 0; j < num_sectors_needed; ++j) {
                set_sector_used(i + j);
            }

            if (write_disk_sector(SECTOR_BITMAP_LBA, sector_bitmap) != 0) {
            }

            return DATA_START_LBA + i;
        }
    }

    return 0;
}

static void free_disk_space(unsigned int start_lba, unsigned int num_byte) {
    if (num_byte == 0) {
        return;
    }

    unsigned int num_sectors_to_free = (num_byte + 511) / 512;

    if (num_sectors_to_free == 0) {
        return;
    }

    if (start_lba < DATA_START_LBA) {
        return;
    }
    unsigned int start_sector_index = start_lba - DATA_START_LBA;

    if (start_sector_index + num_sectors_to_free > NUM_DATA_SECTORS_MANAGED) {
        return;
    }

    for (unsigned int i = 0; i < num_sectors_to_free; ++i) {
        set_sector_free(start_sector_index + i);
    }

    if (write_disk_sector(SECTOR_BITMAP_LBA, sector_bitmap) != 0) {
    }
}

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

static int write_disk_sector(unsigned int lba, const unsigned char* buffer) {
    ata_wait_bsy_clear();
    while (!(inportb(ATA_PRIMARY_STATUS) & ATA_SR_DRDY)) {
        if (inportb(ATA_PRIMARY_STATUS) & ATA_SR_ERR) return 1;
    }

    outportb(ATA_PRIMARY_DRIVE_HEAD, 0xE0 | ((lba >> 24) & 0x0F));

    outportb(ATA_PRIMARY_SECTOR_COUNT, 1);

    outportb(ATA_PRIMARY_LBA_LOW, (unsigned char)(lba & 0xFF));

    outportb(ATA_PRIMARY_LBA_MID, (unsigned char)((lba >> 8) & 0xFF));

    outportb(ATA_PRIMARY_LBA_HIGH, (unsigned char)((lba >> 16) & 0xFF));

    outportb(ATA_PRIMARY_COMMAND, ATA_CMD_WRITE_SECTORS);

    ata_wait_drq_set();
    if (inportb(ATA_PRIMARY_STATUS) & ATA_SR_ERR) {
        return 1;
    }

    for (int i = 0; i < 256; i++) {
        unsigned short data_word = (unsigned short)buffer[i * 2] | (unsigned short)(buffer[i * 2 + 1] << 8);
        outportw(ATA_PRIMARY_DATA, data_word);
    }

    outportb(ATA_PRIMARY_COMMAND, ATA_CMD_CACHE_FLUSH);
    ata_wait_bsy_clear();
    
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

enum EntryType {
    TYPE_FILE,
    TYPE_DIRECTORY,
};

struct File {
    char name[16];
    char content[128];
    int in_use;
    unsigned int content_start_lba;
    unsigned int content_size_bytes;
    enum EntryType type;
    int parent_dir_idx;
};

struct PersistentFileEntry {
    char name[16];
    int in_use;
    unsigned int content_start_lba;
    unsigned int content_size_bytes;
    enum EntryType type;
    int parent_dir_idx;
};

#define MAX_FILES 10
struct File file_table[MAX_FILES];
static int current_working_directory_idx = 0;

static void strncpy_simple(char* dest, const char* src, unsigned int n) {
    unsigned int i;
    for (i = 0; i < n - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

static int fs_create_directory(const char* dirname) {
    if (strlen_simple(dirname) >= sizeof(file_table[0].name)) {
        return 1;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, dirname) == 0 && file_table[i].parent_dir_idx == current_working_directory_idx) {
            return 1;
        }
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 0) {
            strncpy_simple(file_table[i].name, dirname, sizeof(file_table[i].name));
            file_table[i].in_use = 1;
            file_table[i].type = TYPE_DIRECTORY;
            file_table[i].content_start_lba = 0;
            file_table[i].content_size_bytes = 0;
            file_table[i].content[0] = '\0';
            file_table[i].parent_dir_idx = current_working_directory_idx;

            unsigned char sector_buffer[512];
            if (read_disk_sector(FILE_TABLE_LBA, sector_buffer) != 0) {
                for (int k_buf = 0; k_buf < 512; k_buf++) sector_buffer[k_buf] = 0;
            }

            struct PersistentFileEntry* persistent_entries = (struct PersistentFileEntry*)sector_buffer;
            int max_persistent_entries_in_sector = 512 / sizeof(struct PersistentFileEntry);

            if (i < max_persistent_entries_in_sector) {
                strncpy_simple(persistent_entries[i].name, file_table[i].name, sizeof(persistent_entries[i].name));
                persistent_entries[i].in_use = 1;
                persistent_entries[i].type = TYPE_DIRECTORY;
                persistent_entries[i].content_start_lba = 0;
                persistent_entries[i].content_size_bytes = 0;
                persistent_entries[i].parent_dir_idx = file_table[i].parent_dir_idx;
            } else {
                file_table[i].in_use = 0;
                return 1;
            }

            if (write_disk_sector(FILE_TABLE_LBA, sector_buffer) != 0) {
                file_table[i].in_use = 0;
                return 1;
            }

            return 0;
        }
    }
    return 1;
}

static void reverse_string(char* str, int length) {
    int start = 0;
    int end = length - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
}

#define MAX_PATH_LENGTH 256

static void get_current_path_string(char* buffer, int buffer_size) {
    if (buffer_size <= 0) return;
    buffer[0] = '\0';

    if (current_working_directory_idx == 0) {
        if (buffer_size > 1) {
            buffer[0] = '/';
            buffer[1] = '\0';
        }
        return;
    }

    char temp_path[MAX_PATH_LENGTH];
    int temp_path_len = 0;
    int current_dir_idx_walker = current_working_directory_idx;

    while (current_dir_idx_walker != 0 && temp_path_len < MAX_PATH_LENGTH - 1) {
        int name_len = strlen_simple(file_table[current_dir_idx_walker].name);
        if (temp_path_len + name_len + 1 >= MAX_PATH_LENGTH) {
            break;
        }
        for (int i = name_len - 1; i >= 0; i--) {
            if (temp_path_len < MAX_PATH_LENGTH - 1) {
                temp_path[temp_path_len++] = file_table[current_dir_idx_walker].name[i];
            } else break;
        }
        if (temp_path_len < MAX_PATH_LENGTH - 1) {
            temp_path[temp_path_len++] = '/';
        } else break;

        current_dir_idx_walker = file_table[current_dir_idx_walker].parent_dir_idx;
    }
    temp_path[temp_path_len] = '\0';

    reverse_string(temp_path, temp_path_len);

    if (buffer_size > temp_path_len + 1) {
        buffer[0] = '/';
        strncpy_simple(buffer + 1, temp_path, buffer_size - 1);
        buffer[temp_path_len + 1] = '\0';
    } else if (buffer_size > 0) {
        buffer[0] = '\0';
    }

    if (buffer[0] == '/' && buffer[1] == '/' && buffer[2] == '\0') {
        buffer[1] = '\0';
    }
    if (buffer[0] == '/' && buffer[1] == '/' && temp_path_len > 0) {
        int k = 0;
        while (buffer[k+1] != '\0' && k < buffer_size - 1) {
            buffer[k] = buffer[k + 1];
            k++;
        }
        buffer[k] = '\0';
    }

    if (strlen_simple(buffer) == 0 && current_working_directory_idx == 0) {
        if (buffer_size > 1) {
            buffer[0] = '/';
            buffer[1] = '\0';
        }
    } else if (strlen_simple(buffer) > 1 && buffer[0] == '/' && buffer[strlen_simple(buffer) - 1] == '/' && current_working_directory_idx != 0) {
        buffer[strlen_simple(buffer) - 1] = '\0';
    }
}

static int fs_change_directory(const char* path) {
    if (strcmp_simple(path, "/") == 0) {
        current_working_directory_idx = 0;
        return 0;
    }

    if (strcmp_simple(path, ".") == 0) {
        return 0;
    }

    if (strcmp_simple(path, "..") == 0) {
        if (current_working_directory_idx != 0) {
            current_working_directory_idx = file_table[current_working_directory_idx].parent_dir_idx;
        }
        return 0;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && file_table[i].type == TYPE_DIRECTORY && file_table[i].parent_dir_idx == current_working_directory_idx && strcmp_simple(file_table[i].name, path) == 0) {
            current_working_directory_idx = i;
            return 0;
        }
    }

    return 1;
}

static int fs_create_file(const char* filename) {
    if (strlen_simple(filename) >= sizeof(file_table[0].name)) {
        return 1;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, filename) == 0 && file_table[i].parent_dir_idx == current_working_directory_idx) {
            return 1;
        }
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 0) {
            strncpy_simple(file_table[i].name, filename, sizeof(file_table[i].name));
            file_table[i].in_use = 1;
            file_table[i].content[0] = '\0';
            file_table[i].content_start_lba = 0;
            file_table[i].content_size_bytes = 0;
            file_table[i].type = TYPE_FILE;
            file_table[i].parent_dir_idx = current_working_directory_idx;

            unsigned char sector_buffer[512];
            if (read_disk_sector(FILE_TABLE_LBA, sector_buffer) != 0) {
                for (int k_buf = 0; k_buf < 512; k_buf++) sector_buffer[k_buf] = 0;
            }

            struct PersistentFileEntry* persistent_entries = (struct PersistentFileEntry*)sector_buffer;
            int max_persistent_entries_in_sector = 512 / sizeof(struct PersistentFileEntry);

            if (i < max_persistent_entries_in_sector) {
                 strncpy_simple(persistent_entries[i].name, file_table[i].name, sizeof(persistent_entries[i].name));
                 persistent_entries[i].in_use = 1;
                 persistent_entries[i].content_start_lba = 0;
                 persistent_entries[i].content_size_bytes = 0;
                 persistent_entries[i].type = TYPE_FILE;
                 persistent_entries[i].parent_dir_idx = file_table[i].parent_dir_idx;
            } else {
                file_table[i].in_use = 0;
                return 1;
            }
            
            if (write_disk_sector(FILE_TABLE_LBA, sector_buffer) != 0) {
                file_table[i].in_use = 0;
                return 1;
            }

            return 0;
        }
    }
    return 1;
}

static int fs_write_file(const char* filename, const char* data) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, filename) == 0 && file_table[i].parent_dir_idx == current_working_directory_idx && file_table[i].type == TYPE_FILE) {
            unsigned int data_len = strlen_simple(data);

            if (file_table[i].content_start_lba != 0 && file_table[i].content_size_bytes > 0) {
                free_disk_space(file_table[i].content_start_lba, file_table[i].content_size_bytes);
                file_table[i].content_start_lba = 0;
                file_table[i].content_size_bytes = 0;
            }

            if (data_len == 0) {
                file_table[i].content[0] = '\0';
                file_table[i].content_start_lba = 0;
                file_table[i].content_size_bytes = 0;

                unsigned char sector_buffer_ft[512];
                if (read_disk_sector(FILE_TABLE_LBA, sector_buffer_ft) != 0) { return 1; }
                struct PersistentFileEntry* persistent_entries = (struct PersistentFileEntry*)sector_buffer_ft;
                int max_persistent_entries_in_sector = 512 / sizeof(struct PersistentFileEntry);
                if (i < max_persistent_entries_in_sector) {
                    persistent_entries[i].content_start_lba = 0;
                    persistent_entries[i].content_size_bytes = 0;
                } else { return 1; }
                if (write_disk_sector(FILE_TABLE_LBA, sector_buffer_ft) != 0) { return 1; }
                return 0;
            }

            unsigned int new_lba = allocate_disk_space(data_len);
            if (new_lba == 0) {
                return 1;
            }

            unsigned int bytes_written = 0;
            unsigned int current_lba_data = new_lba;
            unsigned char sector_buffer_data[512];

            while (bytes_written < data_len) {
                unsigned int bytes_to_write_this_sector = data_len - bytes_written;
                if (bytes_to_write_this_sector > 512) {
                    bytes_to_write_this_sector = 512;
                }

                for (unsigned int k = 0; k < 512; k++) sector_buffer_data[k] = 0;
                for (unsigned int k = 0; k < bytes_to_write_this_sector; k++) {
                    sector_buffer_data[k] = data[bytes_written + k];
                }

                if (write_disk_sector(current_lba_data, sector_buffer_data) != 0) {
                    free_disk_space(new_lba, data_len);
                    return 1;
                }
                bytes_written += bytes_to_write_this_sector;
                current_lba_data++;
            }

            file_table[i].content_start_lba = new_lba;
            file_table[i].content_size_bytes = data_len;
            if (data_len < sizeof(file_table[i].content)) {
                strncpy_simple(file_table[i].content, data, sizeof(file_table[i].content));
            } else {
                file_table[i].content[0] = '\0';
            }

            unsigned char sector_buffer_ft[512];
            if (read_disk_sector(FILE_TABLE_LBA, sector_buffer_ft) != 0) {
                return 1;
            }
            struct PersistentFileEntry* persistent_entries = (struct PersistentFileEntry*)sector_buffer_ft;
            int max_persistent_entries_in_sector = 512 / sizeof(struct PersistentFileEntry);

            if (i < max_persistent_entries_in_sector) {
                persistent_entries[i].content_start_lba = new_lba;
                persistent_entries[i].content_size_bytes = data_len;
            } else { return 1; }
            
            if (write_disk_sector(FILE_TABLE_LBA, sector_buffer_ft) != 0) {
                return 1;
            }

            return 0;
        }
    }
    return 1;
}

static int fs_delete_file(const char* filename) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, filename) == 0 && file_table[i].parent_dir_idx == current_working_directory_idx && file_table[i].type == TYPE_FILE) {
            if (file_table[i].content_start_lba != 0 && file_table[i].content_size_bytes > 0) {
                free_disk_space(file_table[i].content_start_lba, file_table[i].content_size_bytes);
            }

            file_table[i].in_use = 0;
            file_table[i].name[0] = '\0'; 
            file_table[i].content[0] = '\0'; 
            file_table[i].content_start_lba = 0;
            file_table[i].content_size_bytes = 0;

            unsigned char sector_buffer[512];
            if (read_disk_sector(FILE_TABLE_LBA, sector_buffer) != 0) {
                return 1;
            }

            struct PersistentFileEntry* persistent_entries = (struct PersistentFileEntry*)sector_buffer;
            int max_persistent_entries_in_sector = 512 / sizeof(struct PersistentFileEntry);

            if (i < max_persistent_entries_in_sector) {
                persistent_entries[i].in_use = 0;
                persistent_entries[i].name[0] = '\0'; 
                persistent_entries[i].content_start_lba = 0;
                persistent_entries[i].content_size_bytes = 0;
            } else { 
                return 1;
            }
            
            if (write_disk_sector(FILE_TABLE_LBA, sector_buffer) != 0) {
                return 1;
            }

            return 0;
        }
    }
    return 1;
}

static int fs_delete_directory(const char* dirname) {
    int dir_to_delete_idx = -1;

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, dirname) == 0 && file_table[i].type == TYPE_DIRECTORY && file_table[i].parent_dir_idx == current_working_directory_idx) {
            dir_to_delete_idx = i;
            break;
        }
    }

    if (dir_to_delete_idx == -1) {
        return 1;
    }

    if (dir_to_delete_idx == 0) {
        return 1;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && file_table[i].parent_dir_idx == dir_to_delete_idx) {
            return 1;
        }
    }

    file_table[dir_to_delete_idx].in_use = 0;
    file_table[dir_to_delete_idx].name[0] = '\0';

    unsigned char sector_buffer[512];
    if (read_disk_sector(FILE_TABLE_LBA, sector_buffer) != 0) {
        file_table[dir_to_delete_idx].in_use = 1;
        return 1;
    }

    struct PersistentFileEntry* persistent_entries = (struct PersistentFileEntry*)sector_buffer;
    int max_persistent_entries_in_sector = 512 / sizeof(struct PersistentFileEntry);

    if (dir_to_delete_idx < max_persistent_entries_in_sector) {
        persistent_entries[dir_to_delete_idx].in_use = 0;
        persistent_entries[dir_to_delete_idx].name[0] = '\0';
    } else {
        file_table[dir_to_delete_idx].in_use = 1;
        return 1;
    }

    if (write_disk_sector(FILE_TABLE_LBA, sector_buffer) != 0) {
        file_table[dir_to_delete_idx].in_use = 1;
        return 1;
    }

    return 0;
}

static int fs_read_file(
    const char* filename,
    char* vidptr,
    unsigned int* cursor_pos_ptr,
    unsigned int screen_width_chars,
    unsigned int screen_height_chars,
    unsigned int screen_total_bytes
) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (file_table[i].in_use == 1 && strcmp_simple(file_table[i].name, filename) == 0 && file_table[i].parent_dir_idx == current_working_directory_idx && file_table[i].type == TYPE_FILE) {
            if (file_table[i].content_start_lba == 0 || file_table[i].content_size_bytes == 0) {
                unsigned int current_row_for_newline = (*cursor_pos_ptr / 2) / screen_width_chars;
                *cursor_pos_ptr = (current_row_for_newline + 1) * screen_width_chars * 2;
                if (*cursor_pos_ptr >= screen_total_bytes) {
                     *cursor_pos_ptr = (screen_height_chars - 1) * screen_width_chars * 2;
                }
                return 0;
            }

            unsigned char sector_buffer[512];
            unsigned int bytes_processed_from_disk = 0;
            unsigned int current_lba_data = file_table[i].content_start_lba;
            unsigned int total_bytes_to_display = file_table[i].content_size_bytes;

            while (bytes_processed_from_disk < total_bytes_to_display) {
                if (read_disk_sector(current_lba_data, sector_buffer) != 0) {
                    const char* read_err_msg = "[Read Error]";
                    unsigned int k_err = 0;
                    while(read_err_msg[k_err] != '\0' && *cursor_pos_ptr < screen_total_bytes - 2) {
                        vidptr[*cursor_pos_ptr] = read_err_msg[k_err];
                        vidptr[*cursor_pos_ptr + 1] = 0x0C;
                        *cursor_pos_ptr += 2;
                        k_err++;
                    }
                    return 1;
                }

                unsigned int bytes_to_process_this_sector = total_bytes_to_display - bytes_processed_from_disk;
                if (bytes_to_process_this_sector > 512) {
                    bytes_to_process_this_sector = 512;
                }

                for (unsigned int char_idx_in_sector = 0; char_idx_in_sector < bytes_to_process_this_sector; char_idx_in_sector++) {
                    char current_char = sector_buffer[char_idx_in_sector];
                    
                    if (*cursor_pos_ptr >= screen_total_bytes -2 && current_char != '\n') {
                         return 0;
                    }

                    if (current_char == '\n') {
                        unsigned int current_row_for_newline = (*cursor_pos_ptr / 2) / screen_width_chars;
                        *cursor_pos_ptr = (current_row_for_newline + 1) * screen_width_chars * 2;
                        if (*cursor_pos_ptr >= screen_total_bytes) {
                            *cursor_pos_ptr = (screen_height_chars - 1) * screen_width_chars * 2;
                            return 0;
                        }
                    } else {
                        vidptr[*cursor_pos_ptr] = current_char;
                        vidptr[*cursor_pos_ptr + 1] = 0x07;
                        *cursor_pos_ptr += 2;
                    }
                }
                bytes_processed_from_disk += bytes_to_process_this_sector;
                current_lba_data++;
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
        if (file_table[i].in_use == 1 && file_table[i].parent_dir_idx == current_working_directory_idx) {
            if ((*cursor_pos_ptr / 2) % screen_width_chars != 0) {
                unsigned int current_row_for_newline = (*cursor_pos_ptr / 2) / screen_width_chars;
                *cursor_pos_ptr = (current_row_for_newline + 1) * screen_width_chars * 2;
            }
            if (*cursor_pos_ptr >= screen_total_bytes) {
                *cursor_pos_ptr = (screen_height_chars - 1) * screen_width_chars * 2;
                break;
            }

            unsigned int name_idx = 0;
            while (file_table[i].name[name_idx] != '\0' && *cursor_pos_ptr < screen_total_bytes - 2) {
                vidptr[*cursor_pos_ptr] = file_table[i].name[name_idx];
                vidptr[*cursor_pos_ptr + 1] = 0x07;
                *cursor_pos_ptr += 2;
                name_idx++;
            }

            if (file_table[i].type == TYPE_DIRECTORY) {
                if (*cursor_pos_ptr < screen_total_bytes - 2) {
                    vidptr[*cursor_pos_ptr] = '/';
                    vidptr[*cursor_pos_ptr + 1] = 0x07;
                    *cursor_pos_ptr += 2;
                }
            }

            unsigned int current_row = (*cursor_pos_ptr / 2) / screen_width_chars;
            
            unsigned int row_of_last_char_printed = ((*cursor_pos_ptr - 2) / 2) / screen_width_chars;
            *cursor_pos_ptr = (row_of_last_char_printed + 1) * screen_width_chars * 2;

            if (*cursor_pos_ptr >= screen_total_bytes) {
                *cursor_pos_ptr = (screen_height_chars - 1) * screen_width_chars * 2;
                if (row_of_last_char_printed >= screen_height_chars - 1) break;
            }
        }
    }
}

static void fs_init(void) {
    unsigned char file_table_sector_buffer[512];
    int file_table_loaded_successfully = 0;

    current_working_directory_idx = 0;

    for (int i = 0; i < MAX_FILES; i++) {
        file_table[i].in_use = 0;
        file_table[i].content_start_lba = 0;
        file_table[i].content_size_bytes = 0;
        file_table[i].content[0] = '\0';
        file_table[i].type = TYPE_FILE;
        file_table[i].parent_dir_idx = 0;
    }

    if (read_disk_sector(FILE_TABLE_LBA, file_table_sector_buffer) == 0) {
        file_table_loaded_successfully = 1;
        struct PersistentFileEntry* persistent_entries = (struct PersistentFileEntry*)file_table_sector_buffer;
        int max_persistent_entries_in_sector = 512 / sizeof(struct PersistentFileEntry);

        for (int i = 0; i < MAX_FILES && i < max_persistent_entries_in_sector; i++) {
            if (persistent_entries[i].in_use == 1) {
                strncpy_simple(file_table[i].name, persistent_entries[i].name, sizeof(file_table[i].name));
                file_table[i].in_use = 1;
                file_table[i].content_start_lba = persistent_entries[i].content_start_lba;
                file_table[i].content_size_bytes = persistent_entries[i].content_size_bytes;
                file_table[i].type = persistent_entries[i].type;
                file_table[i].parent_dir_idx = persistent_entries[i].parent_dir_idx;
                file_table[i].content[0] = '\0';
            } else {
                file_table[i].in_use = 0;
                file_table[i].name[0] = '\0';
                file_table[i].content_start_lba = 0;
                file_table[i].content_size_bytes = 0;
                file_table[i].type = TYPE_FILE;
                file_table[i].parent_dir_idx = 0;
            }
        }
    } else {
        for (int k_buf = 0; k_buf < 512; k_buf++) file_table_sector_buffer[k_buf] = 0;
    }

    int root_dir_needs_initialization = 0;
    if (!file_table_loaded_successfully || file_table[0].in_use == 0 || file_table[0].type != TYPE_DIRECTORY || strcmp_simple(file_table[0].name, "/") != 0 || file_table[0].parent_dir_idx != 0) {
        root_dir_needs_initialization = 1;
        strncpy_simple(file_table[0].name, "/", sizeof(file_table[0].name));
        file_table[0].in_use = 1;
        file_table[0].type = TYPE_DIRECTORY;
        file_table[0].content_start_lba = 0;
        file_table[0].content_size_bytes = 0;
        file_table[0].parent_dir_idx = 0;
        file_table[0].content[0] = '\0';
    }

    if (root_dir_needs_initialization) {
        struct PersistentFileEntry* persistent_entries = (struct PersistentFileEntry*)file_table_sector_buffer;
        int max_persistent_entries_in_sector = 512 / sizeof(struct PersistentFileEntry);

        if (0 < max_persistent_entries_in_sector) {
            strncpy_simple(persistent_entries[0].name, file_table[0].name, sizeof(persistent_entries[0].name));
            persistent_entries[0].in_use = file_table[0].in_use;
            persistent_entries[0].type = file_table[0].type;
            persistent_entries[0].content_start_lba = file_table[0].content_start_lba;
            persistent_entries[0].content_size_bytes = file_table[0].content_size_bytes;
            persistent_entries[0].parent_dir_idx = file_table[0].parent_dir_idx;

            if (write_disk_sector(FILE_TABLE_LBA, file_table_sector_buffer) != 0) {
            }
        }
    }

    if (read_disk_sector(SECTOR_BITMAP_LBA, sector_bitmap) != 0) {
        for (int i = 0; i < SECTOR_BITMAP_SIZE_BYTES; i++) {
            sector_bitmap[i] = 0;
        }
        write_disk_sector(SECTOR_BITMAP_LBA, sector_bitmap);
    }
}

void kmain(void) {
    char current_path_prompt[MAX_PATH_LENGTH + 3];
    char path_buffer[MAX_PATH_LENGTH];

    char *vidptr = (char*)0xb8000;
    unsigned int loop_idx;

    unsigned int cursor_pos = 0;
    unsigned int current_line_input_start_offset = 0;

    const unsigned int screen_width_chars = 80;
    const unsigned int screen_height_chars = 25;
    const unsigned int screen_total_bytes = screen_width_chars * screen_height_chars * 2;
    // const unsigned int prompt_len_chars = strlen_simple(prompt_display_str);
    // const unsigned int prompt_len_bytes = prompt_len_chars * 2;

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

    unsigned char test_buffer[512];
    unsigned char read_buffer[512];
    const unsigned int test_lba = 10000;
    int success = 1;

    for (int i = 0; i < 512; i++) {
        test_buffer[i] = (unsigned char)(i % 256);
    }

    if (write_disk_sector(test_lba, test_buffer) != 0) {
        success = 0;
    }

    if (success) {
        for (int i = 0; i < 512; i++) {
            read_buffer[i] = 0;
        }

        if (read_disk_sector(test_lba, read_buffer) != 0) {
            success = 0;
        }
    }

    if (success) {
        for (int i = 0; i < 512; i++) {
            if (read_buffer[i] != test_buffer[i]) {
                success = 0;
                break;
            }
        }
    }

    if (success) {
        vidptr[0] = 'Y';
        vidptr[1] = 0x0A;
    } else {
        vidptr[0] = 'Y';
        vidptr[1] = 0x0C;
    }

    while(1) {
        get_current_path_string(path_buffer, MAX_PATH_LENGTH);
        unsigned int path_len = strlen_simple(path_buffer);

        if (path_len + 3 <= sizeof(current_path_prompt)) {
            strncpy_simple(current_path_prompt, path_buffer, sizeof(current_path_prompt));
            current_path_prompt[path_len] = ' ';
            if (path_len > 1 || (path_len == 1 && path_buffer[0] != '/')) {
                current_path_prompt[path_len] = ' ';
            }
            if (path_len == 1 && path_buffer[0] == '/') {
                current_path_prompt[path_len] = ' ';
                current_path_prompt[path_len + 1] = '>';
                current_path_prompt[path_len + 2] = ' ';
                current_path_prompt[path_len + 3] = '\0';
            } else if (path_len > 0) {
                current_path_prompt[path_len + 1] = '>';
                current_path_prompt[path_len + 2] = ' ';
                current_path_prompt[path_len + 3] = '\0';
            } else {
                current_path_prompt[path_len] = '>';
                current_path_prompt[path_len + 1] = ' ';
                current_path_prompt[path_len + 2] = '\0';
            }
        } else {
            strncpy_simple(current_path_prompt, "> ", sizeof(current_path_prompt));
        }
        if(strlen_simple(current_path_prompt) == 0) {
            strncpy_simple(current_path_prompt, "> ", sizeof(current_path_prompt));
        }

        const char *prompt_display_str = current_path_prompt;
        const unsigned int prompt_len_chars = strlen_simple(prompt_display_str);
        const unsigned int prompt_len_bytes = prompt_len_chars * 2;

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
                    } else if (strncmp_simple(command_buffer, "mkdir ", 6) == 0) {
                        command_found = 1;
                        const char* dirname_to_create = command_buffer + 6;
                        const char* msg;
                        if (strlen_simple(dirname_to_create) > 0) {
                            if (fs_create_directory(dirname_to_create) == 0) {
                                msg = "Directory created.";
                            } else {
                                msg = "Error creating directory (full or invalid name).";
                            }
                        } else {
                            msg = "Usage: mkdir <dirname>";
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
                    } else if (strncmp_simple(command_buffer, "cd ", 3) == 0) {
                        command_found = 1;
                        const char* path_to_change = command_buffer + 3;
                        const char* msg;
                        if (strlen_simple(path_to_change) > 0) {
                            if (fs_change_directory(path_to_change) == 0) {
                                msg = NULL; 
                            } else {
                                msg = "Error: Directory not found or invalid path.";
                            }
                        } else {
                            if (fs_change_directory("/") == 0) {
                                msg = NULL;
                            } else {
                                msg = "Usage: cd <path>";
                            }
                        }
                        if (msg) {
                            unsigned int k = 0;
                            if (cursor_pos < screen_total_bytes) {
                                while(msg[k] != '\0' && cursor_pos < screen_total_bytes) {
                                    vidptr[cursor_pos] = msg[k];
                                    vidptr[cursor_pos+1] = 0x07;
                                    cursor_pos += 2;
                                    k++;
                                }
                            }
                        }
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
                            if (fs_read_file(filename_to_read, vidptr, &cursor_pos, screen_width_chars, screen_height_chars, screen_total_bytes) != 0) {
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
                    } else if (strncmp_simple(command_buffer, "rmdir ", 6) == 0) {
                        command_found = 1;
                        const char* dirname_to_delete = command_buffer + 6;
                        const char* msg;
                        if (strlen_simple(dirname_to_delete) > 0) {
                            if (fs_delete_directory(dirname_to_delete) == 0) {
                                msg = "Directory deleted.";
                            } else {
                                msg = "Error deleting directory (not found or not empty).";
                            }
                        } else {
                            msg = "Usage: rmdir <dirname>";
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
                            if (fs_read_file(filename_to_read, vidptr, &cursor_pos, screen_width_chars, screen_height_chars, screen_total_bytes) != 0) {
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
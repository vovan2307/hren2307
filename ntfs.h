#ifndef _NTFS_H_
#define _NTFS_H_
#pragma pack(push, 1)

typedef enum
{
	AT_STANDARD_INFORMATION = 0x10,
	AT_ATTRIBUTE_LIST       = 0x20,
	AT_FILE_NAME            = 0x30,
	AT_OBJECT_ID = 0x40,
	AT_SECURITY_DESCRIPTOR = 0x50,
	AT_VOLUME_NAME = 0x60,
	AT_VOLUME_INFORMATION = 0x70,
	AT_DATA = 0x80,
	AT_INDEX_ROOT = 0x90,
	AT_INDEX_ALLOCATION = 0xa0,
	AT_BITMAP = 0xb0,
	AT_REPARSE_POINT = 0xc0,
	AT_EA_INFORMATION =   0xd0,
	AT_EA             =   0xe0,
	AT_PROPERTY_SET   =   0xf0,
	AT_LOGGED_UTILITY_STREAM = 0x100,
	AT_USER_DEFINED_FIRST    = 0x1000,
	AT_END = 0xffffffff
} ATTRIBUTE_TYPE_CODE;

typedef struct _BIOS_PARAMETER_BLOCK
{
	/*0x0b*/USHORT bytes_per_sector;	/* ������ �������, � ������ */
	/*0x0d*/UCHAR  sectors_per_cluster;	/* �������� � �������� */
	/*0x0e*/USHORT reserved_sectors;		/* ������ ���� ���� */
	/*0x10*/UCHAR  fats;			/* ������ ���� ���� */
	/*0x11*/USHORT root_entries;		/* ������ ���� ���� */
	/*0x13*/USHORT sectors;			/* ������ ���� ���� */
	/*0x15*/UCHAR  media_type;		/* ��� ��������, 0xf8 = hard disk */
	/*0x16*/USHORT sectors_per_fat;		/* ������ ���� ���� */
	/*0x18*/USHORT sectors_per_track;	/* �� ������������ */
	/*0x1a*/USHORT heads;			/* �� ������������ */
	/*0x1c*/ULONG hidden_sectors;		/* �� ������������ */
	/*0x20*/ULONG large_sectors;		/* ������ ���� ���� */
	/* sizeof() = 25 (0x19) bytes */
} BIOS_PARAMETER_BLOCK, *PBIOS_PARAMETER_BLOCK;

typedef struct _NTFS_BOOT_SECTOR
{
	/*0x00*/UCHAR  jump[3];			/* ������� �� ����������� ��� */
	/*0x03*/ULARGE_INTEGER oem_id;	/* ��������� "NTFS    ". */
	/*0x0b*/BIOS_PARAMETER_BLOCK bpb;
	/*0x24*/UCHAR physical_drive;		/* �� ������������ */
	/*0x25*/UCHAR current_head;		/* �� ������������ */
	/*0x26*/UCHAR extended_boot_signature; /* �� ������������ */
	/*0x27*/UCHAR reserved2;			/* �� ������������ */
	/*0x28*/ULARGE_INTEGER number_of_sectors;	/* ���������� �������� �� ����. */
	/*0x30*/ULARGE_INTEGER mft_lcn;	/* ��������� ������� MFT. */
	/*0x38*/ULARGE_INTEGER mftmirr_lcn;/* ��������� ������� ����� MFT */
	/*0x40*/CHAR  clusters_per_mft_record;	/* ������ MFT ������ � ���������. */
	/*0x41*/UCHAR  reserved0[3];		/* ��������������� */
	/*0x44*/CHAR  clusters_per_index_record;/* ������ ��������� ������ � ���������. */
	/*0x45*/UCHAR  reserved1[3];		/* ��������������� */
	/*0x48*/ULARGE_INTEGER volume_serial_number;	/* ���������� �������� ����� ���� */
	/*0x50*/ULONG checksum;			/* �� ������������ */
	/*0x54*/UCHAR  bootstrap[426];		/* �����������-��� */
	/*0x1fe*/USHORT end_of_sector_marker;	/* ����� ������������ �������, ��������� 0xaa55 */
	/* sizeof() = 512 (0x200) bytes */
} NTFS_BOOT_SECTOR, *PNTFS_BOOT_SECTOR;
typedef struct _MFT_REF
{
	DWORD  indexLow;   //������ �������� � �������
	USHORT indexHigh;
	USHORT ordinal;    //���������� �����
}MFT_REF;

typedef struct _STANDARD_INFORMATION_RECORD {
/*0x0*/   FILETIME creation_time;
/*0x8*/	  FILETIME modification_time;
/*0x10*/  FILETIME entry_modification_time;
/*0x18*/  FILETIME access_time;
/*0x20*/  DWORD    file_attribute_flags;
/*0x24*/  DWORD    maximum_number_of_versions;
/*0x28*/  DWORD    version_number;
/*0x2C*/  DWORD    class_identifier;
/*0x30*/  DWORD    owner_identifier;
/*0x34*/  DWORD    security_descriptor_identifier;
/*0x38*/  DWORD    quota_charged[2];
/*0x40*/  DWORD    update_sequence_number[2];
/*0x48*/  
} STANDARD_INFORMATION_RECORD, *PSTANDARD_INFORMATION;

typedef struct _MFT_RECORD_HEADER
{
	/* The signature Contains: "FILE" */
	BYTE signature[4];
	/* The fixup values offset */
	USHORT fixup_values_offset;
	/* The number of fixup values */
	USHORT number_of_fixup_values;
	/* The journal sequence number */
	DWORD journal_sequence_number[2];
	/* The sequence (value) */
	USHORT sequence;
	/* The reference (link) count */
	USHORT reference_count;
	USHORT attributes_offset;
	USHORT flags;
	DWORD used_entry_size;
	DWORD total_entry_size;
	MFT_REF parent_record_file_reference;
	USHORT first_available_attribute_identifier;
	BYTE unknown1[2];
	DWORD index;
	//size - 48 b
} MFT_RECORD_HEADER, *PMFT_RECORD_HEADER;

typedef struct _ATTRIBUTE_LIST_HEADER{
	union{ DWORD type; ATTRIBUTE_TYPE_CODE type1; };
	USHORT size;
	BYTE name_size;
	BYTE name_offset;
	DWORD data_first_vcn[2];
	MFT_REF file_reference;
	USHORT identifier;
}ATTRIBUTE_LIST_HEADER;

typedef struct _ATTR_RECORD{
/*0x00*/
	union{ DWORD type; ATTRIBUTE_TYPE_CODE type1; };
/*0x04*/	USHORT length; //����� ���������; ������������ ��� �������� � ����������   ��������
/*0x06*/	USHORT Reserved;
/*0x08*/	UCHAR non_resident; //1 ���� ������� �������������, 0 - �����������
/*0x09*/	UCHAR name_length; //����� ����� ��������, � ��������
/*0x0A*/	USHORT name_offset; //�������� ����� ��������, ������������ ��������� 
//��������
/*0x0C*/	USHORT flags; //�����, ����������� � ATTR_FLAGS
/*0x0E*/	USHORT instance;

union
{
	//����������� �������
	struct
	{
		/*0x10*/	ULONG value_length; //������, � ������, ���� ��������
		/*0x14*/	USHORT value_offset; //�������� �������� ����, ������������ ��������� 
		//��������
		/*0x16*/	UCHAR resident_flags; //�����, ����������� � RESIDENT_ATTR_FLAGS
		/*0x17*/	UCHAR reserved;
	} r;
	//������������� �������
	struct
	{
		/*0x10*/	ULARGE_INTEGER lowest_vcn;
		/*0x18*/	ULARGE_INTEGER highest_vcn;
		/*0x20*/	USHORT mapping_pairs_offset;//�������� ������ �������� 
		/*0x22*/	UCHAR compression_unit;
		/*0x23*/	UCHAR reserved1[5];
		/*0x28*/	ULARGE_INTEGER allocated_size; //������ ��������� ������������, 
		//������� ���� �������� ��� ����
		//��������
		/*0x30*/	ULARGE_INTEGER data_size; //�������� ������ ��������
		/*0x38*/	ULARGE_INTEGER initialized_size;
	} nr;
};
} ATTR_RECORD, *PATTR_RECORD;

typedef struct _INDEX_HEADER //��������� ����
{
	/*0x00*/	ULONG entries_offset; //�������� �������� ������� ���������� ��������, ������������ ��������� ����
	/*0x04*/	ULONG index_length; //������ ���� � ������
	/*0x08*/	ULONG allocated_size; //���������� ������ ����
	/*0x0C*/	ULONG flags;
} INDEX_HEADER, *PINDEX_HEADER;

typedef enum _INDEX_ENTRY_FLAGS
{
	INDEX_ENTRY_NODE = 1,
	INDEX_ENTRY_END = 2 //��������� ������� � ����
} INDEX_ENTRY_FLAGS;

typedef struct _FILE_NAME_ATTR{
	/* The parent file reference */
	MFT_REF parent_file_reference;
	FILETIME creation_time;
	FILETIME modification_time;
	FILETIME entry_modification_time;
	FILETIME access_time;
	DWORD allocated_file_size[2];
	DWORD file_size[2];
	DWORD file_attribute_flags;
	DWORD extended_data;
	/* Contains the number of characters without the end-of-string character*/
	BYTE name_size;
	/* The namespace */
	BYTE name_space;
	WCHAR namebody[1];
}FILE_NAME_ATTR;
typedef struct _INDEX_ENTRY_HEADER_DIR //��������� ���������� ��������
{
	/*0x00*/	MFT_REF indexed_file; //����� MFT �����
	/*0x08*/	USHORT length; //�������� ���������� ��������, ������������ ��������
	/*0x0A*/	USHORT key_length; //����� �������� $FILE_NAME
	/*0x0C*/	union{ DWORD flags; INDEX_ENTRY_FLAGS flags1; }; //�����
	/*0x10*/    FILE_NAME_ATTR file_name;//��� ������� FILE_NAME, ���� key_length ������ ����.
} INDEX_ENTRY_HEADER_DIR, *PINDEX_ENTRY_HEADER_DIR;

typedef struct _INDEX_ROOT //��������� $INDEX_ROOT
{
	/*0x00*/	union{ DWORD type; ATTRIBUTE_TYPE_CODE type1; }; //��� �������������� ��������
	/*0x04*/	ULONG collation_rule;      //������� ������������ � ������
	/*0x08*/	ULONG index_block_size;    //������ ��������� ������ � ������ 
	/*0x0C*/	UCHAR clusters_per_index_block; //size of each index block (record) in clusters 
	//���� �������� �������
	/*0x0D*/	UCHAR reserved[3]; //unused
	/*0x10*/	INDEX_HEADER index; //��������� ���������� ����
} INDEX_ROOT, *PINDEX_ROOT;

typedef struct _INDEX_ALLOCATION //��������� ��������� ������
{
	/*0x00*/	ULONG magic; //��������� "INDX"
	/*0x04*/	USHORT usa_ofs;
	/*0x06*/	USHORT usa_count;
	/*0x08*/	ULARGE_INTEGER lsn;
	/*0x10*/	ULARGE_INTEGER index_block_vcn; //VCN ��������� ������
	/*0x18*/	INDEX_HEADER index; //��������� ����
} INDEX_ALLOCATION, *PINDEX_ALLOCATION;

typedef struct _NTFS_VOLUME_CONTEXT{
	HANDLE hvolume;
	DWORD letter;
	DWORD sectorsize; // �������� �������� ����� �������
	DWORD clustersize; // �������� �������� ����� ��������
	DWORD mft_begin[2];
	DWORD mft_record_size; // �������� �������� ������� ������ MFT
	DWORD index_block_size; // ������ ����� ������� � ������
	BYTE  *mft_data;
	BYTE  *mft_stack;       // �������, ��� ������� ����� MFT ������ 32
	BYTE  *indexdata;
	BYTE *indexdata_stack; // �������, ��� ������� ����� �������� ������ 32
	DWORD indexdata_vcn;   // vcn ���� � index allocation
	DWORD dir_fragments;             // ���������� ���������� ��������
	DWORD max_dir_fragments;         // ������������ ���������� ���������� ��������
	DWORD *dir_fragment_offsets;     // lcn ������� ���������
	DWORD *dir_fragment_lens;        // ����� � ��������� ������� ���������
	WCHAR *Upcase;
	DWORD volumesize[2];
	DWORD mft_fragments; // ���������� ���������� MFT
	DWORD mft_fragment_lens[64];
	DWORD mft_fragment_offsets[64];   // �������, ��� ���������� MFT ������ 32
}NTFS_VOLUME_CONTEXT;
#pragma pack(pop)

#endif
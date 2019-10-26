#include <windows.h>
#include <stdio.h>
#include "ntfs.h"

HANDLE consoleOut = 0, consoleIn = 0;

NTFS_VOLUME_CONTEXT* _stdcall InitNTFSContext(WCHAR letter);
BOOL _stdcall ValidateNTFSContext(NTFS_VOLUME_CONTEXT *context);
BOOL _stdcall FreeNTFSContext(NTFS_VOLUME_CONTEXT *context);
// pathlen меньше 0, если функция должна сама найти длину строки в символах
BOOL _stdcall Get_MFT_EntryForPath(NTFS_VOLUME_CONTEXT **context, WCHAR *path, int pathlen, MFT_REF *result);
// Возвращает запись MFT по её номеру
MFT_RECORD_HEADER * ReadMFTEntry(MFT_REF entry, NTFS_VOLUME_CONTEXT *context);
// Возвращает запись MFT для файла или каталога внутри каталога
FILE_NAME_ATTR *GetMFT_Filename(MFT_RECORD_HEADER *pmft);
BOOL Get_MFT_EntryForName(NTFS_VOLUME_CONTEXT *context, WCHAR *filename, DWORD namelen, MFT_REF *result);
// lcn_len_pairs -- массив вида [lcnLow, lcnHigh, length], [lcnLow, lcnHigh, length], ...
BOOL _stdcall GetFileClusters(NTFS_VOLUME_CONTEXT *context, MFT_REF fileref, DWORD *buflen, DWORD *lcn_len_pairs);
// From attribute list
BOOL _stdcall GetFileClustersAL(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *mftrecord, DWORD *buflen, DWORD *lcn_len_pairs);
BOOL StrInStr(BYTE *substr, DWORD sublen, BYTE *str, DWORD len, DWORD *pos, BOOL part);
BOOL BufferedReadFileSync(HANDLE hFile, BYTE *output, DWORD nbytes, DWORD *read, BYTE *buffer, DWORD buflen);

BOOL FindInIndexRoot(NTFS_VOLUME_CONTEXT *context, INDEX_ROOT *root, WCHAR *filename, DWORD namelen, MFT_REF *result);
BOOL FindInIndexAllocation(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *alloc, WCHAR *filename, DWORD namelen,
	BYTE *bitmap, DWORD bitmaplen, MFT_REF *result);
// Поиск в нерезидентной записи
BOOL FindInIndexRecord(NTFS_VOLUME_CONTEXT *context, DWORD lcnLow, DWORD lcnHigh, WCHAR *filename, DWORD namelen, MFT_REF *result);
// Если ci!=0, то нужна таблица upcaseTable, которая содержит 2^16 приведений из малого регистра в большой.
// Если strleft младше чем strright, то функция возвращает -1, если строки равны, то 0, иначе 1.
// Использовать функцию осторожно, она полагает, что память под строки выделена.
int CmpStringW(WCHAR *strleft, DWORD leftlen, WCHAR *strright, DWORD rightlen, WCHAR *upcaseTable, BOOL ci);

NTFS_VOLUME_CONTEXT * _stdcall InitNTFSContext(WCHAR letter){
	WCHAR buffer[24] = { 0 };
	DWORD bitlen = 0, fsize[2];

	NTFS_VOLUME_CONTEXT *context = malloc(sizeof(NTFS_VOLUME_CONTEXT));
	if (context == 0) return 0;

	memset(context, 0, sizeof(NTFS_VOLUME_CONTEXT));

	buffer[0] = letter; buffer[1] = ':'; buffer[2] = 0;
	
	if (GetDiskFreeSpaceW(buffer, &context[0].clustersize, &context[0].sectorsize, &context[0].mft_fragments, context[0].volumesize)==0) return 0;

	context[0].clustersize *= context[0].sectorsize;
	context[0].mft_fragments = 0;

	buffer[0] = '\\'; buffer[1] = '\\'; buffer[2] = '.';
	buffer[3] = '\\'; buffer[4] = letter; buffer[5] = ':';
	buffer[6] = 0;

	context[0].hvolume = CreateFileW(buffer, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (context[0].hvolume == INVALID_HANDLE_VALUE){ context[0].hvolume=0; return 0; }
	
	context[0].Upcase = VirtualAlloc(0, 1 << 17, MEM_COMMIT, PAGE_READWRITE);
	NTFS_BOOT_SECTOR *boot = context[0].Upcase;
	SetFilePointer(context[0].hvolume, 0, NULL, FILE_BEGIN);
	ReadFile(context[0].hvolume, boot, context[0].sectorsize, fsize, NULL);	
	// Расчёт логарифма размера кластера
	while (context[0].clustersize > 63){ bitlen += 6; context[0].clustersize >>= 6; }
	while (context[0].clustersize > 1){ bitlen++; context[0].clustersize >>= 1; }
	context[0].clustersize = bitlen;

	context[0].mft_begin[0] = boot[0].mft_lcn.LowPart;
	context[0].mft_begin[1] = boot[0].mft_lcn.HighPart;
	// Расчёт смещения MFT
	bitlen = context[0].clustersize;
	context[0].mft_begin[1] <<= bitlen;
	context[0].mft_begin[1] |= context[0].mft_begin[0] >> (32 - bitlen);
	context[0].mft_begin[0] <<= bitlen;
	context[0].index_block_size = boot[0].clusters_per_index_record<<bitlen;

	context[0].volumesize[0] = boot[0].number_of_sectors.LowPart;
	context[0].volumesize[1] = boot[0].number_of_sectors.HighPart;
	// Расчёт логарифма размера сектора
	bitlen = 0;
	while (context[0].sectorsize > 63){ bitlen += 6; context[0].sectorsize >>= 6; }
	while (context[0].sectorsize > 1){ bitlen++; context[0].sectorsize >>= 1; }	
	context[0].sectorsize = bitlen;
	
	context[0].volumesize[1] <<= bitlen;
	context[0].volumesize[1] |= context[0].volumesize[0] >> (32 - bitlen);
	context[0].volumesize[0] <<= bitlen;
	
	context[0].mft_record_size = -boot[0].clusters_per_mft_record;
	context[0].mft_stack=context[0].mft_data = malloc(1<<(context[0].mft_record_size+1));
	context[0].indexdata_stack = context[0].indexdata = malloc(context[0].index_block_size << 5);

	for (DWORD i = 0; i < (1 << 16); i++) context[0].Upcase[i] = i;
	CharUpperBuffW(context[0].Upcase, 1 << 16);

	SetFilePointer(context[0].hvolume, context[0].mft_begin[0], context[0].mft_begin + 1, FILE_BEGIN);
	ReadFile(context[0].hvolume, context[0].mft_data, 1<<(context[0].mft_record_size), fsize, NULL);

	MFT_RECORD_HEADER* mftfirst = context[0].mft_data;
	BYTE *mft_record_cursor = mftfirst;
	mft_record_cursor += mftfirst[0].attributes_offset;
	ATTR_RECORD *attribute = mft_record_cursor;
	for (;;){
		attribute = mft_record_cursor;
		if (attribute[0].type == AT_DATA) break;
		if (attribute[0].type == AT_END) break;
		mft_record_cursor += attribute[0].length;
	}
	if (attribute[0].type == AT_END) return 0;

	BYTE *datarun = mft_record_cursor + attribute[0].nr.mapping_pairs_offset;
	for (DWORD i=0; datarun[0];i++){
		DWORD subbytes = datarun[0];
		datarun++;
		BYTE *bval = context[0].mft_fragment_lens + i * 2;
		DWORD j=0, len = (subbytes & 15);
		for (; j < len; j++) bval[j] = datarun[j]; // Длина отрезка в кластерах
		datarun += len;
		len = subbytes >> 4;
		bval = context[0].mft_fragment_offsets + i * 2;
		for (j=0; j < len; j++) bval[j] = datarun[j]; // Логический или виртуальный номер кластера
		datarun += len;
		context[0].mft_fragments++;
	}
	for (DWORD i = 1, j = 2; i < context[0].mft_fragments; i++, j += 2){// Перевод из VCN в lcn
		context[0].mft_fragment_offsets[j] += context[0].mft_fragment_offsets[j - 2];
		context[0].mft_fragment_offsets[j + 1] += context[0].mft_fragment_offsets[j - 1];
	}
	// Перевод из размера в кластерах в размер в байтах
	for (DWORD i = 0, j = 0; i < context[0].mft_fragments; i++, j += 2){
		context[0].mft_fragment_lens[j + 1] <<= context[0].clustersize;
		context[0].mft_fragment_lens[j + 1] |= context[0].mft_fragment_lens[j] >> (32 - context[0].clustersize);
		context[0].mft_fragment_lens[j] <<= context[0].clustersize;

		context[0].mft_fragment_offsets[j + 1] <<= context[0].clustersize;
		context[0].mft_fragment_offsets[j + 1] |= context[0].mft_fragment_offsets[j] >> (32 - context[0].clustersize);
		context[0].mft_fragment_offsets[j] <<= context[0].clustersize;
	}
	context[0].dir_fragment_offsets = malloc(32 * 2 * 4);
	context[0].dir_fragment_lens = context[0].dir_fragment_offsets + 32;
	context[0].max_dir_fragments = 32;

	return context;
}
BOOL _stdcall ValidateNTFSContext(NTFS_VOLUME_CONTEXT *context){
	BYTE *buffer = context;

	if (context == 0) return 0;
	__try{
		buffer[0] = buffer[0];
	}
	__except (EXCEPTION_EXECUTE_HANDLER){
		return 0;
	}
	if (context[0].hvolume == 0) return 0;
	if (context[0].indexdata == 0) return 0;
	if (context[0].mft_data == 0) return 0;
	if (context[0].max_dir_fragments < 32) return 0;
	if (context[0].dir_fragment_offsets == 0) return 0;
	if (context[0].Upcase == 0) return 0;
	
	return 1;
}
BOOL _stdcall FreeNTFSContext(NTFS_VOLUME_CONTEXT *context){
	if (context == 0) return 0;
	if (context[0].hvolume) CloseHandle(context[0].hvolume);
	if (context[0].Upcase) VirtualFree(context[0].Upcase, 0, MEM_RELEASE);
	if (context[0].mft_data) free(context[0].mft_data);
	if (context[0].indexdata) free(context[0].indexdata);

	context[0].hvolume = 0; context[0].Upcase = 0; 
	context[0].mft_stack=context[0].mft_data = 0;
	context[0].indexdata_stack=context[0].indexdata = 0;
	return 1;
}
MFT_RECORD_HEADER * ReadMFTEntry(MFT_REF entry, NTFS_VOLUME_CONTEXT *context){
	if (context == 0) return 0;
	DWORD *mftoffset = &entry, *lens=context[0].mft_fragment_lens;
	entry.ordinal = 0;
	// Перевод из номера записи в номер байта
	mftoffset[1] <<= context[0].mft_record_size;
	mftoffset[1] |= mftoffset[0] >> (32 - context[0].mft_record_size);
	mftoffset[0] <<= context[0].mft_record_size;
	
	DWORD countsize[2] = { 0 };
	DWORD fragment = -1;
	// Находим номер фрагмента mft
	for (DWORD i = 0, j = 0; i < context[0].mft_fragments; i++, j += 2){
		fragment = i;
		if (mftoffset[1] < lens[j+1]) break;
		if (mftoffset[1] == lens[j+1] && mftoffset[0] < lens[j]) break;
		// Переводим смещение относительно начала mft в смещение относительно начала фрагмента mft
		mftoffset[0] -= lens[j];
		if (mftoffset[0]>lens[j]) mftoffset[1]--;
		mftoffset[1] -= lens[j+1];
	}

	if (mftoffset[1] > lens[fragment*2+1]) return 0;
	if (mftoffset[1] == lens[fragment*2+1] && mftoffset[0] > lens[fragment*2]) return 0;

	DWORD diskpos[2] = { 0 };
	diskpos[0] = context[0].mft_fragment_offsets[fragment * 2];
	diskpos[1] = context[0].mft_fragment_offsets[fragment * 2 + 1];

	diskpos[0] += mftoffset[0];
	if (diskpos[0] < mftoffset[0]) diskpos[1]++;
	diskpos[1] += mftoffset[1];

	SetFilePointer(context[0].hvolume, diskpos[0], diskpos + 1, FILE_BEGIN);
	ReadFile(context[0].hvolume, context[0].mft_stack, 1 << context[0].mft_record_size, diskpos + 1, NULL);

	return context[0].mft_stack;
}
BOOL _stdcall GetFileClusters(NTFS_VOLUME_CONTEXT *context, MFT_REF fileref, DWORD *buflen, DWORD *lcn_len_pairs){
	if (context == 0 || buflen == 0 || lcn_len_pairs == 0) return 0;

	if (ReadMFTEntry(fileref, context) == 0){ SetLastError(ERROR_FILE_NOT_FOUND); return 0; }
	BYTE *mft_record_buffer = context[0].mft_stack;
	MFT_RECORD_HEADER *header = mft_record_buffer;
	ATTRIBUTE_LIST_HEADER *attrlist = 0;

	mft_record_buffer += header[0].attributes_offset;
	ATTR_RECORD *mftattr = 0, *dataattr=0, *listattr=0;
	DWORD counted = 0, vcn=0, lcn=0;
	BYTE *runlist = 0, *bvcn=&vcn;

	for (;;){
		mftattr = mft_record_buffer;
		if (mftattr[0].type == AT_END) break;
		if (mftattr[0].type == AT_ATTRIBUTE_LIST){ listattr = mft_record_buffer; break; }
		if (mftattr[0].type == AT_DATA){ dataattr=mftattr; break; }
		mft_record_buffer += mftattr[0].length;
	}

	if (listattr == 0){
		if (dataattr == 0) return 0;
		if (dataattr[0].non_resident == 0) { buflen[0] = 0; return 0; }
		runlist = (BYTE*)dataattr + mftattr[0].nr.mapping_pairs_offset;
	}
	else{ return GetFileClustersAL(context, listattr, buflen, lcn_len_pairs); }
	for (DWORD j=0;;){
		j = runlist[0]; runlist++;
		if (j == 0) break;
		runlist += (j & 15) + (j >> 4);
		counted++;
	}
	if (buflen[0] < counted){ SetLastError(ERROR_INSUFFICIENT_BUFFER); buflen[0] = counted; return 0; }
	else { buflen[0] = counted; }

	runlist = (BYTE*)dataattr + mftattr[0].nr.mapping_pairs_offset;
	for (DWORD i=0, i1=0, j = 0, k=0;;){
		j = runlist[0]; runlist++;
		if (j == 0) break;
		lcn_len_pairs[i1+1]= lcn_len_pairs[i1 + 2] = 0;
		// Выписать длину фрагмента
		bvcn = lcn_len_pairs + i1+2;		
		for (k = 0; k < (j & 15); k++) bvcn[k] = runlist[k];
		runlist += j & 15; vcn = 0; bvcn = &vcn;
		// Выписать номер кластера
		for (k = 0; k < (j>>4); k++) bvcn[k] = runlist[k];
		if (bvcn[k - 1] & 0x80){ for (; k < 4; k++) bvcn[k] = 0xff; }
		lcn += vcn;	lcn_len_pairs[i1] = lcn;

		runlist += j >> 4;
		i++; i1 += 3;
	}
	return 1;
}
BOOL GetFileClustersAL(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *mftrecord, DWORD *buflen, DWORD *lcn_len_pairs){
	ATTRIBUTE_LIST_HEADER *listattr = 0;
	BYTE *cursor = mftrecord;
	DWORD count = 0, counted=0;
	cursor += mftrecord[0].r.value_offset;

	for (;;){
		listattr = cursor;
		if (listattr[0].type == AT_END) break;
		cursor += listattr[0].size;
		if (listattr[0].type == AT_ATTRIBUTE_LIST || listattr[0].type == AT_DATA){
			count = 0;
			context[0].mft_stack += 1 << context[0].mft_record_size;
			GetFileClusters(context, listattr[0].file_reference, &count, lcn_len_pairs);
			context[0].mft_stack -= 1 << context[0].mft_record_size;
			counted += count;
		}
	}
	if (counted > buflen[0]){ SetLastError(ERROR_INSUFFICIENT_BUFFER); buflen[0] = counted; 
		return 0; }
	
	buflen[0] = counted; counted = 0; count = buflen[0];
	cursor = mftrecord; cursor += mftrecord[0].r.value_offset;

	for (;;){
		listattr = cursor;
		if (listattr[0].type == AT_END) break;
		cursor += listattr[0].size;
		if (listattr[0].type == AT_ATTRIBUTE_LIST || listattr[0].type == AT_DATA){
			count = buflen[0] - counted;
			context[0].mft_stack += 1 << context[0].mft_record_size;
			GetFileClusters(context, listattr[0].file_reference, &count, lcn_len_pairs + counted * 3);
			context[0].mft_stack -= 1 << context[0].mft_record_size;
			counted += count;
		}
	}
	SetLastError(0); buflen[0] = counted;
	return 1;
}
// pathlen меньше 0, если функция должна сама найти длину строки в символах
BOOL _stdcall Get_MFT_EntryForPath(NTFS_VOLUME_CONTEXT **context, WCHAR *path, int pathlen, MFT_REF *result){
	if (context == 0 || path == 0 || result == 0) return 0;

	result[0].indexLow = -1; result[0].indexHigh = result[0].ordinal = -1;
	__try{
		// Если pathlen не задан, то найти
		if (pathlen < 0){ for (pathlen = 0; path[pathlen]; pathlen++); }
	}
	__except (EXCEPTION_EXECUTE_HANDLER){
		return 0;
	}
	DWORD left = 0, current = 0, written = 0, retcode = 0, index=0;
	BYTE c = 0;

	for (current = left; current < pathlen; current++) { if (path[current] == ':') break; }
	if (current == pathlen && path[current] != ':') return 0;
#ifdef _DEBUG
	WriteConsoleW(consoleOut, path + left, current - left, &written, NULL);
	WriteConsoleW(consoleOut, L"\r\n", 2, &written, NULL);
#endif
	current++;
	if (current == pathlen) return 0;
	c = path[current];
	if (c == '/' || c == '\\'); else return 0;

	if (context[0] == 0){
		context[0] = InitNTFSContext(path[0]);
		if (context[0] == 0) { return 0; }
		if (ValidateNTFSContext(context[0]) == 0){ FreeNTFSContext(context[0]); return 0; }
	}
	result[0].indexHigh=result[0].ordinal = 0; result[0].indexLow = 5;

	left = current + 1;
	for (DWORD i=0;;i++){
		for (current = left; current < pathlen; current++) {
			c = path[current]; if (c == '/' || c == '\\') break;
		}
		written = current - left;
		if (written == 0) break;
		ReadMFTEntry(result[0], context[0]);
		retcode = Get_MFT_EntryForName(context[0], path + left, written, result);
		if (retcode == 0) break;
#ifdef _DEBUG
		WriteConsoleW(consoleOut, path + left, written, &written, NULL);
		WriteConsoleW(consoleOut, L"\r\n", 2, &written, NULL);
#endif
		if (current == pathlen) break;
		if (c == '/' || c == '\\') current++;
		left = current;
	}
	return retcode;
}
int CmpStringW(WCHAR *strleft, DWORD leftlen, WCHAR *strright, DWORD rightlen, WCHAR *upcaseTable, BOOL ci){
	DWORD len = leftlen, i=0;
	WCHAR cleft = 0, cright = 0;
	if (rightlen < leftlen) len = rightlen;
	for (i = 0; i < len; i++){
		cleft = strleft[i]; cright = strright[i];
		if (ci){ cleft = upcaseTable[cleft]; cright = upcaseTable[cright]; }
		if (cleft < cright) return -1;
		if (cleft > cright) return 1;
	}
	if (leftlen < rightlen) return -1;
	if (leftlen > rightlen) return 1;
	return 0;
}
BOOL StrInStr(BYTE *substr, DWORD sublen, BYTE *str, DWORD len, DWORD *pos, BOOL part){
	DWORD i = 0, j=0, k=0, last = len - sublen;
	for (i = 0; i <= last; i++){
		for (j = 0, k = 0; j < sublen; j++, k++){
			if (substr[j] != str[i + k]) break;
		}
		if (j == sublen) { pos[0] = i; return 1; }
	}
	if (part == 0){ pos[0] = len + 1; return 1; }
	sublen--;
	for (; i < len; i++, sublen--){
		for (j = 0, k = i; j < sublen; j++, k++) if (substr[j] != str[k]) break;
		if (j == sublen) { pos[0] = i; return 1; }
	}
	pos[0] = len + 1; return 1;
}

BOOL BufferedReadFileSync(HANDLE hFile, BYTE *output, DWORD nbytes, DWORD *read, BYTE *buffer, DWORD buflen){
	DWORD i = 0, read1=0, tocopy=buflen;
	BOOL result = 0;
	for (; i < nbytes;){
		read1 = 0;
		result = ReadFile(hFile, buffer, buflen, &read1, NULL);
		if (result == 0) break;
		if (nbytes - i < buflen) tocopy = nbytes - i;
		memcpy_s(output + i, nbytes - i, buffer, tocopy);
		i += tocopy;
		if (i >= nbytes) break;
	}
	read[0] = i;
	return 0;
}

FILE_NAME_ATTR *GetMFT_Filename(MFT_RECORD_HEADER *pmft){
	if (pmft == 0) return 0;
	BYTE *mft_record_cursor = pmft;
	mft_record_cursor += pmft[0].attributes_offset;
	ATTR_RECORD *mft_attr = mft_record_cursor;
	ATTR_RECORD *nameattr = 0;
	for (;;){
		mft_attr = mft_record_cursor;
		if (mft_attr[0].type == AT_END) break;
		if (mft_attr[0].type == AT_FILE_NAME) nameattr = mft_attr;
		mft_record_cursor += mft_attr[0].length;
	}
	if (nameattr == 0) return 0;
	mft_record_cursor = nameattr;
	mft_record_cursor += nameattr[0].r.value_offset;
	return mft_record_cursor;
}

BOOL FindInIndexRecord(NTFS_VOLUME_CONTEXT *context, DWORD lcnLow, DWORD lcnHigh, WCHAR *filename, DWORD namelen, MFT_REF *result){
	result[0].ordinal = result[0].indexHigh = -1; result[0].indexLow = -1;
	context[0].indexdata_vcn = -1;

	lcnHigh <<= context[0].clustersize;
	lcnHigh |= lcnLow >> (32 - context[0].clustersize);
	lcnLow <<= context[0].clustersize;

	DWORD read = 0, *pvcn=0;
	BYTE *buffer_cursor = context[0].indexdata_stack;
	INDEX_ALLOCATION *alloc = buffer_cursor;
	INDEX_ENTRY_HEADER_DIR *dirheader = 0;

	SetFilePointer(context[0].hvolume, lcnLow, &lcnHigh, FILE_BEGIN);
	ReadFile(context[0].hvolume, buffer_cursor, context[0].index_block_size, &read, NULL);
	
	if (alloc[0].magic != 'XDNI') 
		return 0;

	buffer_cursor = &alloc[0].index;
	buffer_cursor += alloc[0].index.entries_offset;
	for (DWORD i=0,k=0;;){
		dirheader = buffer_cursor; pvcn = 0;
		if (dirheader[0].flags&INDEX_ENTRY_NODE){
#ifdef _DEBUG
			WriteConsoleW(consoleOut, L"has subnode\r\n", sizeof(L"has subnode\r\n")/2-1, &k, NULL);
#endif
			pvcn = buffer_cursor + dirheader[0].length - 8;
		}
		if (dirheader[0].flags&INDEX_ENTRY_END) break;
		buffer_cursor += dirheader[0].length;
		FILE_NAME_ATTR *fname = &dirheader[0].file_name;
		if (fname[0].name_space!=2){
			context[0].mft_stack += 1 << context[0].mft_record_size;
			ReadMFTEntry(dirheader[0].indexed_file, context);
			fname = GetMFT_Filename(context[0].mft_stack);
			context[0].mft_stack -= 1 << context[0].mft_record_size;
		}
#ifdef _DEBUG
		WriteConsoleW(consoleOut, fname[0].namebody, fname[0].name_size, &k, NULL);
		WriteConsoleW(consoleOut, L"\r\n", 2, &k, NULL);
#endif
		int cmp = CmpStringW(filename, namelen, fname[0].namebody, fname[0].name_size, context[0].Upcase, 1);
		if (cmp > 0) continue;
		if (cmp < 0) break;

		result[0] = dirheader[0].indexed_file; return 1;
	}
	if (pvcn){ context[0].indexdata_vcn = pvcn[0]; }
	return 0;
}
BOOL FindInIndexRoot(NTFS_VOLUME_CONTEXT *context, INDEX_ROOT *root, WCHAR *filename, DWORD namelen, MFT_REF *result){
	INDEX_ENTRY_HEADER_DIR *dirheader = 0;
	BYTE *buffer_cursor = &root[0].index;
	buffer_cursor += root[0].index.entries_offset;
	DWORD *pvcn=0;
	DWORD count = 0, written=0;
	int cmp = 0;

	for (count=0;;count++){
		dirheader = buffer_cursor; cmp = -1; pvcn = 0;

		if (dirheader[0].flags&INDEX_ENTRY_NODE){ pvcn = buffer_cursor + dirheader[0].length - 8; }
		if (dirheader[0].flags & INDEX_ENTRY_END) break;
		FILE_NAME_ATTR *fname = &dirheader[0].file_name;

		if (fname[0].name_space != 2){
			context[0].mft_stack += 1 << context[0].mft_record_size;
			ReadMFTEntry(dirheader[0].indexed_file, context);
			fname = GetMFT_Filename(context[0].mft_stack);
			context[0].mft_stack -= 1 << context[0].mft_record_size;
		}
		cmp = CmpStringW(filename, namelen, fname[0].namebody, fname[0].name_size, context[0].Upcase, 1);
#ifdef _DEBUG
		WriteConsoleW(consoleOut, fname[0].namebody, fname[0].name_size, &written, NULL);
		WriteConsoleW(consoleOut, L"\r\n", 2, &written, NULL);
#endif
		if (cmp < 1) break;
		buffer_cursor += dirheader[0].length;
	}
	if (cmp == 0){ result[0] = dirheader[0].indexed_file; return 1; }
	if (pvcn){ context[0].indexdata_vcn = pvcn[0]; }
	return 0;
}
BOOL FindInIndexAllocation(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *alloc, WCHAR *filename, DWORD namelen, 
	BYTE *bitmap, DWORD bitmaplen, MFT_REF *result)
{
	result[0].indexLow = -1; result[0].indexHigh = result[0].ordinal = -1;

	DWORD lcn[2] = { 0 }, vcn[2] = { 0 }, i = 0;
	BYTE *bval = vcn, *runlist=alloc;
	runlist += alloc[0].nr.mapping_pairs_offset;
	BOOL found = 0;

	for (i=0, context[0].dir_fragments=0;;i++){
		DWORD j = runlist[0], k=0; runlist++;
		if (j == 0) break; // Конец списка отрезков
		vcn[1] = vcn[0] = 0;
		context[0].dir_fragment_lens[i] = 0;
		bval = context[0].dir_fragment_lens + i;
		for (k = j & 15; k > 0; k--) bval[k - 1] = runlist[k - 1];
		runlist += j & 15;
		for (bval = vcn, k = j >> 4; k>0; k--) bval[k - 1] = runlist[k - 1];
		// Если последний байт vcn в runlist меньше 0, то дополняем до 32-битного отрицательного числа
		if (bval[(j >> 4) - 1] & 0x80){	for (k = j >> 4; k<4; k++) bval[k] = 0xff;	}
		runlist += j>>4;
		lcn[0] += vcn[0]; context[0].dir_fragment_offsets[i] = lcn[0];
		context[0].dir_fragments = i + 1;
	}
	i = 0;
	for (;;){
		vcn[0] = context[0].indexdata_vcn;
		if (vcn[0] == -1 || vcn[0]>alloc[0].nr.highest_vcn.LowPart) break;
		
		for (i = 0; i < context[0].dir_fragments; i++){
			if (vcn[0] < context[0].dir_fragment_lens[i]) break;
			vcn[0] -= context[0].dir_fragment_lens[i];
		}
		if (i == context[0].dir_fragments){// Если встретится неправильный runlist
			vcn[0] += context[0].dir_fragment_lens[i - 1]; i--;
		}
		lcn[0] = context[0].dir_fragment_offsets[i];
		vcn[0] += lcn[0];
		found = FindInIndexRecord(context, vcn[0], 0, filename, namelen, result);
		if (found) return 1;
	}
	SetLastError(ERROR_FILE_NOT_FOUND); return 0;
}
BOOL Get_MFT_EntryForName(NTFS_VOLUME_CONTEXT *context, WCHAR *filename, DWORD namelen, MFT_REF *result){
	result[0].ordinal = result[0].indexHigh = -1; result[0].indexLow = -1;

	BYTE *mft_record_cursor = context[0].mft_stack;

	MFT_RECORD_HEADER *header = mft_record_cursor;
	mft_record_cursor += header[0].attributes_offset;

	ATTR_RECORD *mft_attr = 0;
	INDEX_ROOT *root = 0;
	INDEX_ALLOCATION *allocation = 0;

	ATTR_RECORD *rootattr = 0, *allocattr = 0, *nameattr = 0, *bitmapattr = 0;
	DWORD vcn[2] = { 0 };

	for (;;){
		mft_attr = mft_record_cursor;
		if (mft_attr[0].type == AT_END) break;
		if (mft_attr[0].type == AT_FILE_NAME) nameattr = mft_attr;
		if (mft_attr[0].type == AT_BITMAP) bitmapattr = mft_attr;
		if (mft_attr[0].type == AT_INDEX_ROOT){ rootattr = mft_attr; root = mft_record_cursor + mft_attr[0].r.value_offset; }
		if (mft_attr[0].type == AT_INDEX_ALLOCATION) { allocattr = mft_attr; }
		mft_record_cursor += mft_attr[0].length;
	}
	BYTE *bitmap = 0, *runlist = 0;
	DWORD bitmaplen = 0;
	
	if (rootattr == 0) { SetLastError(ERROR_PATH_NOT_FOUND); return 0; }
	if (allocattr){ mft_record_cursor = allocattr; runlist = mft_record_cursor + allocattr[0].nr.mapping_pairs_offset; }
	if (bitmapattr){ mft_record_cursor = bitmapattr; bitmap = mft_record_cursor + bitmapattr[0].r.value_offset; bitmaplen = bitmapattr[0].r.value_length; }
	
	FindInIndexRoot(context, root, filename, namelen, result);
	if (result[0].indexHigh != -1 && result[0].indexLow != -1) return 1;
	
	if (allocattr) {
		DWORD found = FindInIndexAllocation(context, allocattr, filename, namelen, bitmap, bitmaplen, result);
		return found;
	}
	return 0;
}

BOOL CALLBACK DllMain(HANDLE hModule, DWORD  Reason, LPVOID lpReserved){
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow){
	DWORD read = 0, index=0, found = 0, inputlen = 0;
	MFT_REF reference = { 0 };
	WCHAR *buffer = 0;
	HANDLE consoleIn = 0;
	NTFS_VOLUME_CONTEXT *context[26] = { 0 };
	DWORD clusters1[24] = { 0 };
	DWORD *clusters = clusters1;

	AllocConsole(); consoleOut = GetStdHandle(STD_OUTPUT_HANDLE); consoleIn = GetStdHandle(STD_INPUT_HANDLE);
	buffer = VirtualAlloc(0, 1 << 15, MEM_COMMIT, PAGE_READWRITE);

	WriteConsoleW(consoleOut, L"Enter path to find in NTFS\r\n", sizeof(L"Enter path to find in NTFS\r\n") / 2 - 1, &read, NULL);
	ReadConsoleW(consoleIn, buffer, 1 << 12, &inputlen, NULL);
	buffer[inputlen - 2] = 0;
	WCHAR letter = buffer[0];
	letter |= 32;

	if (letter < 'a' || letter > 'z') { 
		WriteConsoleW(consoleOut, L"Invalid path\r\n", sizeof(L"Invalid path\r\n") / 2 - 1, &read, NULL);
		return 0;
	}
	index = letter - 'a';
	found=Get_MFT_EntryForPath(context+index, buffer, inputlen-2, &reference);	
	read = 8;
	if (found == 0){
		WriteConsoleW(consoleOut, L"File not found", sizeof(L"File not found") / 2 - 1, &read, NULL);
		WriteConsoleW(consoleOut, L"\r\n", 2, &read, NULL);
	}
	else{
		read = 8;
		WriteConsoleW(consoleOut, L"File found at ", sizeof(L"File found at ") / 2 - 1, &read, NULL);
		read = wsprintfW(buffer, L"%04x%08x", reference.indexHigh, reference.indexLow);
		WriteConsoleW(consoleOut, buffer, read, &read, NULL);
		WriteConsoleW(consoleOut, L"\r\n", 2, &read, NULL);
		found = GetFileClusters(context[index], reference, &read, clusters);
		if (found == 0){
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) clusters = malloc(read * 3 * 4);
			found = GetFileClusters(context[index], reference, &read, clusters);
		}
		if (found){
			DWORD written = 0;
			WriteConsoleW(consoleOut, L"File fragments:\r\n", sizeof(L"File fragments:\r\n") / 2 - 1, &written, 0);
			for (DWORD i = 0, j = 0; i < read; i++, j += 3){
				WCHAR *fmt = L"%x%08x";
				if (clusters[j + 1] == 0) fmt = L"%x%x";
				WriteConsoleW(consoleOut, L"Start cluster : ", sizeof(L"Start cluster: ")/2-1, &written, 0);
				buffer[written = wsprintfW(buffer, fmt, clusters[j + 1], clusters[j])] = 0;
				WriteConsoleW(consoleOut, buffer, written, &written, 0);
				WriteConsoleW(consoleOut, L", length: ", sizeof(L", length: ")/2-1, &written, 0);
				buffer[written = wsprintfW(buffer, L"%08x\r\n", clusters[j + 2])] = 0;
				WriteConsoleW(consoleOut, buffer, written, &written, 0);
			}
		}
	}

	WriteConsoleW(consoleOut, L"Press enter to exit", sizeof(L"Press enter to exit") / 2 - 1, &read, NULL);
	ReadConsoleW(consoleIn, buffer, 4, &read, NULL);
	
	VirtualFree(buffer, 0, MEM_RELEASE);
	FreeConsole();
	return 0;
}
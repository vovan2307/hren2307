#include <windows.h>
#include <stdio.h>
#include "ntfs.h"

#pragma warning (disable: 4133)

HANDLE consoleOut = 0, consoleIn = 0;
FILE *logfiles[16] = { 0 };
DWORD tids[16] = { 0 };
DWORD threads = 0;

FILE *getfp(DWORD tid);

// Заполнение информации о ФС
NTFS_VOLUME_CONTEXT* _stdcall InitNTFSContext(WCHAR letter);

// Проверка информации о ФС
BOOL _stdcall ValidateNTFSContext(NTFS_VOLUME_CONTEXT *context);

// Освобождение структуры от информации о ФС
BOOL _stdcall FreeNTFSContext(NTFS_VOLUME_CONTEXT *context);

// pathlen меньше 0, если функция должна сама найти длину строки в символах
BOOL _stdcall Get_MFT_EntryForPath(NTFS_VOLUME_CONTEXT **context, WCHAR *path, int pathlen, MFT_REF *result);

// Возвращает запись MFT по её номеру
MFT_RECORD_HEADER * ReadMFTEntry(MFT_REF entry, NTFS_VOLUME_CONTEXT *context);

// читает кластер по LCN и возвращает прочитанное целиком
BYTE * ReadCluster(NTFS_VOLUME_CONTEXT *context, DWORD lcnHigh, DWORD lcnLow);

// не используется
BOOL ExpandRunList(BYTE *runlist, DWORD *buflen, DWORD *lcn_len_pairs, BOOL isqword);

// Возвращает смещение тела атрибута FILE_NAME относительно начала записи для файла или каталога внутри каталога по содержимому записи
FILE_NAME_ATTR *GetMFT_Filename(MFT_RECORD_HEADER *pmft);

// возвращает номер записи (структуру) по имени файлового объекта
BOOL Get_MFT_EntryForName(NTFS_VOLUME_CONTEXT *context, WCHAR *filename, DWORD namelen, MFT_REF *result);

// lcn_len_pairs -- массив вида [lcnLow, lcnHigh, length], [lcnLow, lcnHigh, length], ... , принимает контекст ФС, номер записи в виде структуры, количество отрезков для чтения и массив, куда читать
BOOL _stdcall GetFileClusters(NTFS_VOLUME_CONTEXT *context, MFT_REF fileref, DWORD *buflen, DWORD *lcn_len_pairs);

// From resident attribute list :получает контекст, смещение начала AL, количество отрезков и массив, куда их записывать
BOOL _stdcall GetFileClustersAL(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *mftrecord, DWORD *buflen, DWORD *lcn_len_pairs);

// From non resident attribute list :получает контекст, смещение начала AL, количество отрезков и массив, куда их записывать
BOOL _stdcall GetFileClustersALNR(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *mftrecord, DWORD *buflen, DWORD *lcn_len_pairs);

BOOL StrInStr(BYTE *substr, DWORD sublen, BYTE *str, DWORD len, DWORD *pos, BOOL part);
BOOL BufferedReadFileSync(HANDLE hFile, BYTE *output, DWORD nbytes, DWORD *read, BYTE *buffer, DWORD buflen);

// поиск в IR записи (начиная со смещения тела IR) файлового объекта по его имени, возвращает номер записи в виде структуры
BOOL FindInIndexRoot(NTFS_VOLUME_CONTEXT *context, INDEX_ROOT *root, WCHAR *filename, DWORD namelen, MFT_REF *result);

// поиск в IA корневого каталога номера записи(в виде структуры) файлового объекта по имени
BOOL FindInIndexAllocation(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *alloc, WCHAR *filename, DWORD namelen,
	BYTE *bitmap, DWORD bitmaplen, MFT_REF *result);

// поиск записей с AL (не используется)
BOOL FindALRecords(NTFS_VOLUME_CONTEXT *context, DWORD *buflen, DWORD *output);

// Поиск в нерезидентной записи (в найденном кластере из IA ищется запись файлового объекта по имени и возвращается номер записи в виде структуры)
BOOL FindInIndexRecord(NTFS_VOLUME_CONTEXT *context, DWORD lcnLow, DWORD lcnHigh, WCHAR *filename, DWORD namelen, MFT_REF *result);

// Если ci!=0, то нужна таблица upcaseTable, которая содержит 2^16 приведений из малого регистра в большой.
// Если strleft младше чем strright, то функция возвращает -1, если строки равны, то 0, иначе 1.
// Использовать функцию осторожно, она полагает, что память под строки выделена.
int CmpStringW(WCHAR *strleft, DWORD leftlen, WCHAR *strright, DWORD rightlen, WCHAR *upcaseTable, BOOL ci);

FILE *getfp(DWORD tid){
	DWORD i = 0;
	for (i = 0; i < threads; i++) if (tids[i] == tid) return logfiles[i];
	return 0;
}
NTFS_VOLUME_CONTEXT * _stdcall InitNTFSContext(WCHAR letter){
	WCHAR buffer[24] = { 0 };
	DWORD bitlen = 0, fsize[2];

	NTFS_VOLUME_CONTEXT *context = malloc(sizeof(NTFS_VOLUME_CONTEXT));
	if (context == 0) return 0;

	memset(context, 0, sizeof(NTFS_VOLUME_CONTEXT));

	buffer[0] = letter; buffer[1] = ':'; buffer[2] = 0;

	if (GetDiskFreeSpaceW(buffer, &context[0].clustersize, &context[0].sectorsize, &context[0].mft_fragments, context[0].volumesize) == 0) return 0;

	context[0].clustersize *= context[0].sectorsize;
	context[0].mft_fragments = 0;

	buffer[0] = '\\'; buffer[1] = '\\'; buffer[2] = '.';
	buffer[3] = '\\'; buffer[4] = letter; buffer[5] = ':';
	buffer[6] = 0;

	context[0].hvolume = CreateFileW(buffer, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (context[0].hvolume == INVALID_HANDLE_VALUE){ context[0].hvolume = 0; return 0; }

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
	context[0].index_block_size = boot[0].clusters_per_index_record << bitlen;

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
	context[0].mft_stack = context[0].mft_data = malloc(1 << (context[0].mft_record_size + 1));
	context[0].indexdata_stack = context[0].indexdata = malloc(context[0].index_block_size << 5);

	for (DWORD i = 0; i < (1 << 16); i++) context[0].Upcase[i] = i;
	CharUpperBuffW(context[0].Upcase, 1 << 16);

	SetFilePointer(context[0].hvolume, context[0].mft_begin[0], context[0].mft_begin + 1, FILE_BEGIN);
	ReadFile(context[0].hvolume, context[0].mft_data, 1 << (context[0].mft_record_size), fsize, NULL);

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
	for (DWORD i = 0; datarun[0]; i++){
		DWORD subbytes = datarun[0];
		datarun++;
		BYTE *bval = context[0].mft_fragment_lens + i * 2;
		DWORD j = 0, len = (subbytes & 15);
		for (; j < len; j++) bval[j] = datarun[j]; // Длина отрезка в кластерах
		datarun += len;
		len = subbytes >> 4;
		bval = context[0].mft_fragment_offsets + i * 2;
		for (j = 0; j < len; j++) bval[j] = datarun[j]; // Логический или виртуальный номер кластера
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
BOOL _stdcall ValidateNTFSContext(NTFS_VOLUME_CONTEXT *context){ // проферка заполненной инфы о ФС
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
BOOL _stdcall FreeNTFSContext(NTFS_VOLUME_CONTEXT *context){ // освобождение структуры с инфой о ФС
	if (context == 0) return 0;
	if (context[0].hvolume) CloseHandle(context[0].hvolume);
	if (context[0].Upcase) VirtualFree(context[0].Upcase, 0, MEM_RELEASE);
	if (context[0].mft_data) free(context[0].mft_data);
	if (context[0].indexdata) free(context[0].indexdata);

	context[0].hvolume = 0; context[0].Upcase = 0;
	context[0].mft_stack = context[0].mft_data = 0;
	context[0].indexdata_stack = context[0].indexdata = 0;
	return 1;
}
MFT_RECORD_HEADER * ReadMFTEntry(MFT_REF entry, NTFS_VOLUME_CONTEXT *context){ // возвращает запись (содержимое само) мфт по ее номеру (номер в виде структуры из индексного элемента IR)
	if (context == 0) return 0;
	DWORD *mftoffset = &entry, *lens = context[0].mft_fragment_lens;
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
		if (mftoffset[1] < lens[j + 1]) break;
		if (mftoffset[1] == lens[j + 1] && mftoffset[0] < lens[j]) break;
		// Переводим смещение относительно начала mft в смещение относительно начала фрагмента mft
		mftoffset[0] -= lens[j];
		if (mftoffset[0]>lens[j]) mftoffset[1]--;
		mftoffset[1] -= lens[j + 1];
	}

	if (mftoffset[1] > lens[fragment * 2 + 1]) return 0;
	if (mftoffset[1] == lens[fragment * 2 + 1] && mftoffset[0] > lens[fragment * 2]) return 0;

	DWORD diskpos[2] = { 0 };
	diskpos[0] = context[0].mft_fragment_offsets[fragment * 2];
	diskpos[1] = context[0].mft_fragment_offsets[fragment * 2 + 1];

	diskpos[0] += mftoffset[0];
	if (diskpos[0] < mftoffset[0]) diskpos[1]++;
	diskpos[1] += mftoffset[1];
	__try{
		SetFilePointer(context[0].hvolume, diskpos[0], diskpos + 1, FILE_BEGIN);
		ReadFile(context[0].hvolume, context[0].mft_stack, 1 << context[0].mft_record_size, diskpos + 1, NULL);
	}
	__except (EXCEPTION_EXECUTE_HANDLER){
		return 0;
	}
	return context[0].mft_stack;
}
BYTE * ReadCluster(NTFS_VOLUME_CONTEXT *context, DWORD lcnHigh, DWORD lcnLow){ // читает кластер по LCN и возвращает прочитанное целиком
	if (context == 0) return 0;
	lcnHigh <<= context[0].clustersize;
	lcnHigh |= lcnLow >> (32 - context[0].clustersize);
	lcnLow <<= context[0].clustersize;

	SetFilePointer(context[0].hvolume, lcnLow, &lcnHigh, FILE_BEGIN);
	ReadFile(context[0].hvolume, context[0].indexdata_stack, 1 << context[0].clustersize, &lcnLow, 0);
	SetFilePointer(context[0].hvolume, 0, 0, FILE_BEGIN);

	return context[0].indexdata_stack;
}
BOOL ExpandRunList(BYTE *runlist, DWORD *buflen, DWORD *lcn_len_pairs, BOOL isqword){
	DWORD i = 0, j = 0, count = 0, len = 0, lcn[2] = { 0 }, vcn[2] = { 0 };
	BYTE mask = 0, *bval = runlist;
	for (count = 0;; count++){
		mask = runlist[0]; runlist++;
		if (mask == 0) break;
		runlist += mask & 15; runlist += mask >> 4;
	}
	if (count > buflen[0]){ buflen[0] = count; SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
	runlist = bval;

	for (count = 0;; count++){
		mask = runlist[0]; runlist++;
		if (mask == 0) break;
		vcn[0] = vcn[1] = len = 0; bval = &len;
		for (i = 0, j = mask & 15; i < j; i++) bval[i] = runlist[i];
		bval = vcn;
		for (i = 0, j = mask >> 4; i < j; i++) bval[i] = runlist[i];
		if (bval[j - 1] & 0x80){ for (i = j; i < 8; i++) bval[i] = 0xff; }
		lcn[0] += vcn[0];
		if (lcn[0] < vcn[0]) lcn[1]++;
		lcn[1] += vcn[1];
		j = count * 2; if (isqword) j += count;
		lcn_len_pairs[j] = lcn[0]; lcn_len_pairs[j + 1] = lcn[1];
		if (isqword) lcn_len_pairs[j + 2] = len;
	}

	return 1;
}
BOOL _stdcall GetFileClusters(NTFS_VOLUME_CONTEXT *context, MFT_REF fileref, DWORD *buflen, DWORD *lcn_len_pairs){
	if (context == 0 || buflen == 0 || lcn_len_pairs == 0) return 0;
	
	if (fileref.indexHigh>0x8000){
		buflen[0]=0;SetLastError(ERROR_FILE_NOT_FOUND); return 0;}// если передали неправильный номер файловой записи
	if (ReadMFTEntry(fileref, context) == 0){ 
		buflen[0]=0;SetLastError(ERROR_FILE_NOT_FOUND); return 0; } // если нельзя прочитать файловую запись
	
	BYTE *mft_record_buffer = context[0].mft_stack; // на начало считанной записи по номеру
	MFT_RECORD_HEADER *header = mft_record_buffer;
	ATTRIBUTE_LIST_HEADER *attrlist = 0;

	mft_record_buffer += header[0].attributes_offset; // на начало атрибутов
	ATTR_RECORD *mftattr = 0, *dataattr = 0, *listattr = 0;
	DWORD counted = 0, vcn = 0, lcn = 0;
	BYTE *runlist = 0, *bvcn = &vcn;

	for (;;){ // поиск либо AL, либо DATA
		mftattr = mft_record_buffer;
		if (mftattr[0].type == AT_END) break;
		if (mftattr[0].type == AT_ATTRIBUTE_LIST){ listattr = mft_record_buffer; break; }
		if (mftattr[0].type == AT_DATA){ dataattr = mftattr; break; }
		mft_record_buffer += mftattr[0].length;
	}

	if (listattr == 0){ // если нет AL
		if (dataattr == 0) { buflen[0] = 0; return 0; }
		if (dataattr[0].non_resident == 0) { buflen[0] = 0; return 0; } // если резидентный
		runlist = (BYTE*)dataattr + mftattr[0].nr.mapping_pairs_offset; // смещение списка отрезков получаем
	}
	else{
		// получает контекст, смещение начала AL, количество отрезков и массив, куда их записывать
		return GetFileClustersAL(context, listattr, buflen, lcn_len_pairs); // если есть AL
	}
	for (DWORD j = 0;;){
		j = runlist[0]; runlist++;
		if (j == 0) break;
		
		runlist += (j & 15) + (j >> 4);
		counted++; // количество отрезков
	}
	if (buflen[0] < counted){ SetLastError(ERROR_INSUFFICIENT_BUFFER); buflen[0] = counted; return 0; } // если отрезков больше чем выделено памяти под них
	else { buflen[0] = counted; }

	runlist = (BYTE*)dataattr + mftattr[0].nr.mapping_pairs_offset; // на начало списка
	for (DWORD i = 0, i1 = 0, j = 0, k = 0;;){
		j = runlist[0]; runlist++;
		if (j == 0) break;
		if ((j & 15) > 4 || (j >> 4) > 4) break;
		lcn_len_pairs[i1 + 1] = lcn_len_pairs[i1 + 2] = 0;
		// Выписать длину фрагмента
		bvcn = lcn_len_pairs + i1 + 2;
		for (k = 0; k < (j & 15); k++) bvcn[k] = runlist[k];
		runlist += j & 15; vcn = 0; bvcn = &vcn;
		// Выписать номер кластера
		for (k = 0; k < (j >> 4); k++) bvcn[k] = runlist[k];
		if (bvcn[k - 1] & 0x80){ for (; k < 4; k++) bvcn[k] = 0xff; }
		lcn += vcn;	lcn_len_pairs[i1] = lcn; // номер кластера LCN (не VCN)

		runlist += j >> 4; // к следующему отрезку в списке
		i++; i1 += 3;
	}
	return 1;
}
BOOL _stdcall GetFileClustersALNR(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *mftrecord, DWORD *buflen, DWORD *lcn_len_pairs){
	BYTE *cursor = mftrecord, *runlist = 0;
	ATTRIBUTE_LIST_HEADER *listattr = 0;
	runlist = cursor + mftrecord[0].nr.mapping_pairs_offset; // на начало списка отрезков AL
	DWORD len = 0, lcn = 0, vcn = 0, count = 0, counted = 0;
	BYTE mask = 0, *bdata = 0;

	for (DWORD i = 0, j = 0;;){ // распаковка отрезков
		mask = runlist[0]; runlist++;
		if (mask == 0) break;
		vcn = len = 0; bdata = &len;
		for (i = 0, j = mask & 15; i < j; i++) bdata[i] = runlist[i];
		if (len > 1) return 0;
		runlist += mask & 15; bdata = &vcn;
		for (i = 0, j = mask >> 4; i < j; i++) bdata[i] = runlist[i];
		if (bdata[(mask >> 4) - 1] & 0x80){ for (i = mask >> 4; i < 4; i++) bdata[i] = 0xff; }
		runlist += mask >> 4; lcn += vcn;
		for (i = 0; i < len; i++){
			listattr = cursor = ReadCluster(context, 0, lcn + i); // чтение всех кластеров отрезка в index_data stack
			if (cursor == 0) return 0;
			for (;;){ // поиск атрибутов DATA в кластерах AL
				listattr = cursor;
				cursor += listattr[0].size;
				if (listattr[0].size == 0) break;
				if (listattr[0].type != AT_DATA || listattr[0].name_size > 0) continue;
				if (listattr[0].file_reference.indexLow < 0x40) continue;

				// если нашли DATA
				context[0].mft_stack += 1 << context[0].mft_record_size;
				count = 0;
				GetFileClusters(context, listattr[0].file_reference, &count, lcn_len_pairs);  // то ищем список кластеров по номеру записи
				context[0].mft_stack -= 1 << context[0].mft_record_size;
				counted += count;
			}
		}
	}

	if (counted > buflen[0]){ buflen[0] = counted; SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }

	cursor = mftrecord;
	runlist = cursor + mftrecord[0].nr.mapping_pairs_offset;
	buflen[0] = counted; counted = 0; count = buflen[0];

	for (DWORD i = 0, j = 0;;){
		mask = runlist[0]; runlist++;
		if (mask == 0) break;
		lcn = vcn = len = 0; bdata = &len;
		for (i = 0, j = mask & 15; i < j; i++) bdata[i] = runlist[i];
		runlist += mask & 15; bdata = &vcn;
		for (i = 0, j = mask >> 4; i < j; i++) bdata[i] = runlist[i];
		if (bdata[(mask >> 4) - 1] & 0x80){ for (i = mask >> 4; i < 4; i++) bdata[i] = 0xff; }
		runlist += mask >> 4; lcn += vcn;
		for (i = 0; i < len; i++){
			listattr = cursor = ReadCluster(context, 0, lcn + i);
			if (cursor == 0) return 0;
			for (;;){
				listattr = cursor;
				cursor += listattr[0].size;
				if (listattr[0].size == 0) break;
				if (listattr[0].type != AT_DATA || listattr[0].name_size > 0) continue;
				if (listattr[0].file_reference.indexLow < 0x40) continue;

				count = buflen[0] - counted;
				context[0].mft_stack += 1 << context[0].mft_record_size;
				GetFileClusters(context, listattr[0].file_reference, &count, lcn_len_pairs + counted * 3);
				context[0].mft_stack -= 1 << context[0].mft_record_size;
				counted += count;
			}
		}
	}

	return 1;
}
BOOL GetFileClustersAL(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *mftrecord, DWORD *buflen, DWORD *lcn_len_pairs){
	if (mftrecord[0].non_resident) return GetFileClustersALNR(context, mftrecord, buflen, lcn_len_pairs); // Если AL не резидентный, то другую функцию

	ATTRIBUTE_LIST_HEADER *listattr = 0;
	BYTE *cursor = mftrecord;
	DWORD count = 0, counted = 0;
	cursor += mftrecord[0].r.value_offset; // смещение тела AL

	for (;;){ // поиск в теле AL атрибутов DATA или AL
		listattr = cursor;
		if (listattr[0].type == AT_END) break;
		cursor += listattr[0].size; // к следующему атрибуту в списке
		for (; listattr[0].type == AT_ATTRIBUTE_LIST || listattr[0].type == AT_DATA;){
			count = 0;
			if (listattr[0].type == AT_DATA && listattr[0].name_size>0) break;
			if (listattr[0].file_reference.indexLow < 0x40) break; // извлекаем номер записи, где хранится атрибут

			context[0].mft_stack += 1 << context[0].mft_record_size;
			GetFileClusters(context, listattr[0].file_reference, &count, lcn_len_pairs); // получаем списки отрезков из этого атрибута
			context[0].mft_stack -= 1 << context[0].mft_record_size;
			counted += count; // количество отрезков
			break;
		}
	}
	if (counted > buflen[0]){ SetLastError(ERROR_INSUFFICIENT_BUFFER); buflen[0] = counted; return 0; }

	buflen[0] = counted; counted = 0; count = buflen[0];
	cursor = mftrecord; cursor += mftrecord[0].r.value_offset;

	for (;;){
		listattr = cursor;
		if (listattr[0].type == AT_END) break;
		cursor += listattr[0].size;
		for (; listattr[0].type == AT_ATTRIBUTE_LIST || listattr[0].type == AT_DATA;){
			count = buflen[0] - counted;
			if (listattr[0].type == AT_DATA && listattr[0].name_size>0) break;
			if (listattr[0].file_reference.indexLow < 0x40) break;

			context[0].mft_stack += 1 << context[0].mft_record_size;
			GetFileClusters(context, listattr[0].file_reference, &count, lcn_len_pairs + counted * 3);
			context[0].mft_stack -= 1 << context[0].mft_record_size;
			counted += count;
			break;
		}
	}
	SetLastError(0); buflen[0] = counted;
	return 1;
}
// pathlen меньше 0, если функция должна сама найти длину строки в символах; возвращает номер записи MFT (структуру в виде: [indexLow, indexHigh, ordinal] - младшие 32 бита номер записи, старшие 16 бит и номер последовательности) по полному имени файла
BOOL _stdcall Get_MFT_EntryForPath(NTFS_VOLUME_CONTEXT **context, WCHAR *path, int pathlen, MFT_REF *result){  // контекст ФС, путь, длина пути, возвращаемая структура
	if (context == 0 || path == 0 || result == 0) return 0;

	result[0].indexLow = -1; result[0].indexHigh = result[0].ordinal = -1;
	__try{
		// Если pathlen не задан, то найти
		if (pathlen < 0){ for (pathlen = 0; path[pathlen]; pathlen++); }
	}
	__except (EXCEPTION_EXECUTE_HANDLER){
		return 0;
	}
	DWORD left = 0, current = 0, written = 0, retcode = 0, index = 0;
	WCHAR c = 0;

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
		context[0] = InitNTFSContext(path[0]); // заполнение инфы о ФС
		if (context[0] == 0) { return 0; }
		if (ValidateNTFSContext(context[0]) == 0){ FreeNTFSContext(context[0]); return 0; } // проверка инфы о ФС, в случае неправильной инфы - очистка структуры
	}
	result[0].indexHigh = result[0].ordinal = 0; result[0].indexLow = 5; // запись корневого каталога (5-я запись MFT)

	left = current + 1; // на первый символ имени файлового объекта в пути после корневого каталога, после C:/
	for (DWORD i = 0;; i++){
		for (current = left; current < pathlen; current++) {
			c = path[current]; if (c == '/' || c == '\\') break; // получаем имя следующего файлового объекта
		}
		written = current - left; // длина имени файлового объекта
		if (written == 0) break;
		ReadMFTEntry(result[0], context[0]); // чтение файловой записи корневого каталога в стек сначала, затем запись следующего файлового объекта
		retcode = Get_MFT_EntryForName(context[0], path + left, written, result); // возвращает номер записи (в виде структуры) по имени файлового объекта
		if (retcode == 0) break;
#ifdef _DEBUG
		WriteConsoleW(consoleOut, path + left, written, &written, NULL);
		WriteConsoleW(consoleOut, L"\r\n", 2, &written, NULL);
#endif
		if (current == pathlen) break;
		if (c == '/' || c == '\\') current++; // переход к следующему файловому объекту
		left = current;
	}
	return retcode;
}
int CmpStringW(WCHAR *strleft, DWORD leftlen, WCHAR *strright, DWORD rightlen, WCHAR *upcaseTable, BOOL ci){
	DWORD len = leftlen, i = 0;
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
	DWORD i = 0, j = 0, k = 0, last = len - sublen;
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
FILE_NAME_ATTR *GetMFT_Filename(MFT_RECORD_HEADER *pmft){
	if (pmft == 0) return 0;
	BYTE *mft_record_cursor = pmft; // на начало записи
	mft_record_cursor += pmft[0].attributes_offset; // на начало описания атрибутов
	ATTR_RECORD *mft_attr = mft_record_cursor;
	ATTR_RECORD *nameattr = 0;
	FILE_NAME_ATTR *fname = 0;
	for (;;){ // поиск атрибута FILE_NAME
		mft_attr = mft_record_cursor;
		if (mft_attr[0].type == AT_END) break;
		if (mft_attr[0].type == AT_FILE_NAME) nameattr = mft_attr; // смещение атрибута FILE_NAME
		if (nameattr){
			fname = mft_record_cursor + nameattr[0].r.value_offset;
			if (fname[0].name_space != 2) break;
		}
		mft_record_cursor += mft_attr[0].length; // переход к следующему атрибуту
	}
	if (nameattr == 0) return 0;
	mft_record_cursor = nameattr;
	mft_record_cursor += nameattr[0].r.value_offset; // смещение тела атрибута FILE_NAME относительно начала записи
	return mft_record_cursor;
}

BOOL FindALRecords(NTFS_VOLUME_CONTEXT *context, DWORD *buflen, DWORD *output){ // поиск записей с AL
	if (context == 0 || buflen == 0 || output == 0) return 0;
	DWORD index = 0, count = 0;
	BYTE *mft_record_cursor = 0;
	ATTR_RECORD *mftattr = 0, *attrlist = 0;
	MFT_RECORD_HEADER *mftheader = 0;

	MFT_REF reference = { 0 };
	reference.ordinal = reference.indexHigh = 0;
	reference.indexLow = -1;

	for (index = 0;; index++){
		reference.indexLow = index;
		mftheader = ReadMFTEntry(reference, context); // чтение нулевой записи
		if (mftheader == 0) break;
		mft_record_cursor = mftheader;
		mft_record_cursor += mftheader[0].attributes_offset; // на начало атрибутов
		for (attrlist = 0;;){ // Поиск AL 
			mftattr = mft_record_cursor;
			if (mftattr[0].type == AT_END) break;
			if (mftattr[0].type == AT_ATTRIBUTE_LIST){ attrlist = mftattr; break; }
			mft_record_cursor += mftattr[0].length; // Переход к следующему атрибуту
		}
		if (attrlist == 0) continue;
		if (count < buflen[0]) output[count] = index;
		count++;
	}
	if (count > buflen[0]){ buflen[0] = count; SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
	buflen[0] = count;
	SetLastError(0); return 1;
}
BOOL FindInIndexRecord(NTFS_VOLUME_CONTEXT *context, DWORD lcnLow, DWORD lcnHigh, WCHAR *filename, DWORD namelen, MFT_REF *result){
	FILE *logfile = getfp(GetCurrentThreadId());

	result[0].ordinal = result[0].indexHigh = -1; result[0].indexLow = -1;
	context[0].indexdata_vcn = -1;

	lcnHigh <<= context[0].clustersize;
	lcnHigh |= lcnLow >> (32 - context[0].clustersize);
	lcnLow <<= context[0].clustersize;

	DWORD read = 0, *pvcn = 0;
	BYTE *buffer_cursor = context[0].indexdata_stack;
	INDEX_ALLOCATION *alloc = buffer_cursor;
	INDEX_ENTRY_HEADER_DIR *dirheader = 0;

	SetFilePointer(context[0].hvolume, lcnLow, &lcnHigh, FILE_BEGIN);
	ReadFile(context[0].hvolume, buffer_cursor, context[0].index_block_size, &read, NULL);

	if (alloc[0].magic != 'XDNI'){ return 0; }
	buffer_cursor = &alloc[0].index; // на заголовок первого узла
	buffer_cursor += alloc[0].index.entries_offset; // смещение тела первого индексного элемента относительно заголовка узла
	for (DWORD i = 0, k = 0;;){
		dirheader = buffer_cursor; pvcn = 0;
		if (dirheader[0].flags&INDEX_ENTRY_NODE){ // если есть подкаталог (IA)
			pvcn = buffer_cursor + dirheader[0].length - 8; // запоминаем этот подузел
		}
		if (dirheader[0].flags&INDEX_ENTRY_END) break; // если последний элемент
		buffer_cursor += dirheader[0].length; // переход к следующему элементу
		FILE_NAME_ATTR *fname = &dirheader[0].file_name; // получаем атрибут FILE_NAME текущего индексного элемента
		if (fname[0].name_space != 2){
			context[0].mft_stack += 1 << context[0].mft_record_size; // получаем размер записи
			ReadMFTEntry(dirheader[0].indexed_file, context); // возвращает запись мфт (содержимое ее) в контекст по ее номеру (в виде структуры) (в индексном элементе хранится номер записи)
			fname = GetMFT_Filename(context[0].mft_stack); // смещение тела атрибута FILE_NAME относительно начала записи для индексного элемента
			context[0].mft_stack -= 1 << context[0].mft_record_size;
		}
		int cmp = CmpStringW(filename, namelen, fname[0].namebody, fname[0].name_size, context[0].Upcase, 1); // сравнение имени искомого имени файлового объекта с именем текущего элемента
		if (cmp > 0) continue;
		if (cmp < 0) break;
		// если имена равны, то нашли номер записи
		result[0] = dirheader[0].indexed_file; return 1;
	}
	if (pvcn){ context[0].indexdata_vcn = pvcn[0]; } // если подкаталог, то ищем в нем
	return 0;
}
BOOL FindInIndexRoot(NTFS_VOLUME_CONTEXT *context, INDEX_ROOT *root, WCHAR *filename, DWORD namelen, MFT_REF *result){ // поиск в IR записи (начиная со смещения тела IR) файлового объекта по его имени, возвращает номер записи в виде структуры
	INDEX_ENTRY_HEADER_DIR *dirheader = 0;
	BYTE *buffer_cursor = &root[0].index; // на первый заголовок узла
	buffer_cursor += root[0].index.entries_offset; // переходим к первому индексному элементу 
	DWORD *pvcn = 0;
	DWORD count = 0, written = 0;
	int cmp = 0;
	for (count = 0;; count++){
		dirheader = buffer_cursor; cmp = -1; pvcn = 0;
		if (dirheader[0].flags&INDEX_ENTRY_NODE){ pvcn = buffer_cursor + dirheader[0].length - 8; } // если не последний элемент в узле, то получаем смещение следующего		
		FILE_NAME_ATTR *fname = &dirheader[0].file_name; // получаем атрибут FILE_NAME текущего индексного элемента

		if (fname[0].name_space != 2){
			context[0].mft_stack += 1 << context[0].mft_record_size; // получаем размер записи
			ReadMFTEntry(dirheader[0].indexed_file, context); // возвращает запись мфт (содержимое ее) в контекст по ее номеру (в виде структуры) (в индексном элементе хранится номер записи)
			fname = GetMFT_Filename(context[0].mft_stack); // смещение тела атрибута FILE_NAME относительно начала записи для индексного элемента
			context[0].mft_stack -= 1 << context[0].mft_record_size;
		}
		cmp = CmpStringW(filename, namelen, fname[0].namebody, fname[0].name_size, context[0].Upcase, 1); // сравнение искомого имени файла с текущим
		if (cmp < 1) break; // если имя искомого файла меньше имени узла, то искать в нерезидентной группе
		if (dirheader[0].flags & INDEX_ENTRY_END) break;
		buffer_cursor += dirheader[0].length; // к следующему индексному элементу
	}
	if (cmp == 0){ result[0] = dirheader[0].indexed_file; return 1; } // если нашли номер записи в IR, то возвращаем его в виде структуры
	if (pvcn){ context[0].indexdata_vcn = pvcn[0]; } // если не в IR, то получаем VCN узла IA нужной нерезидентной группы

	return 0;
}
BOOL FindInIndexAllocation(NTFS_VOLUME_CONTEXT *context, ATTR_RECORD *alloc, WCHAR *filename, DWORD namelen,
	BYTE *bitmap, DWORD bitmaplen, MFT_REF *result)
{
	result[0].indexLow = -1; result[0].indexHigh = result[0].ordinal = -1;

	DWORD lcn[2] = { 0 }, vcn[2] = { 0 }, i = 0;
	BYTE *bval = vcn, *runlist = alloc; // смещение атрибута IA
	runlist += alloc[0].nr.mapping_pairs_offset; // смещение списка отрезков
	BOOL found = 0;

	// распаковка отрезков IA
	for (i = 0, context[0].dir_fragments = 0;; i++){ // количество фрагментов каталога
		DWORD j = runlist[0], k = 0; runlist++;
		if (j == 0) break; // Конец списка отрезков
		vcn[1] = vcn[0] = 0;
		context[0].dir_fragment_lens[i] = 0; // длина в кластерах каждого фрагмента
		bval = context[0].dir_fragment_lens + i;
		for (k = j & 15; k > 0; k--) bval[k - 1] = runlist[k - 1]; // длина в кластерах фрагмента
		runlist += j & 15;
		for (bval = vcn, k = j >> 4; k>0; k--) bval[k - 1] = runlist[k - 1]; // номер первого кластера фрагмента
		// Если последний байт vcn в runlist меньше 0, то дополняем до 32-битного отрицательного числа
		if (bval[(j >> 4) - 1] & 0x80){ for (k = j >> 4; k<4; k++) bval[k] = 0xff; }
		runlist += j >> 4;
		lcn[0] += vcn[0]; context[0].dir_fragment_offsets[i] = lcn[0]; // номер первого кластера фрагмента (LCN)
		context[0].dir_fragments = i + 1;
	}
	i = 0;
	for (DWORD j = 0; j < bitmaplen * 8;){
		BYTE mask = bitmap[j >> 3];
		if (mask == 0) { j+=8; continue; }// Пропустить 8 кластеров, если байт карты равен 0
		mask &= 1 << (j & 7);
		if (mask == 0){ j++; continue; } // Пропустить 1 кластер, если бит карты равен 0

		vcn[0] = j; // VCN узла из битовой карты vcn
		if (j>alloc[0].nr.highest_vcn.LowPart) break;
		// Цикл нахождения нужного фрагмента IA по номеру vcn
		for (i = 0; i < context[0].dir_fragments; i++){
			if (vcn[0] < context[0].dir_fragment_lens[i]) break;
			vcn[0] -= context[0].dir_fragment_lens[i];
		}
		if (i == context[0].dir_fragments){// Если встретится неправильный runlist
			vcn[0] += context[0].dir_fragment_lens[i - 1]; i--;
		}
		lcn[0] = context[0].dir_fragment_offsets[i]; // номер первого кластера фрагмента (LCN)
		vcn[0] += lcn[0];
		found = FindInIndexRecord(context, vcn[0], 0, filename, namelen, result); // в найденном кластере ищется запись файлового объекта по имени и возвращается номер записи в виде структуры
		if (found) return 1;
		j++; // Идём дальше по битовой карте
	}
	SetLastError(ERROR_FILE_NOT_FOUND); return 0;
}
BOOL Get_MFT_EntryForName(NTFS_VOLUME_CONTEXT *context, WCHAR *filename, DWORD namelen, MFT_REF *result){
	result[0].ordinal = result[0].indexHigh = -1; result[0].indexLow = -1;

	BYTE *mft_record_cursor = context[0].mft_stack; // содержимое записи корневого каталога (или следующего файлового объекта)

	MFT_RECORD_HEADER *header = mft_record_cursor;
	mft_record_cursor += header[0].attributes_offset; // смещение начала атрибутов относительно начала записи

	ATTR_RECORD *mft_attr = 0;
	INDEX_ROOT *root = 0;
	INDEX_ALLOCATION *allocation = 0;

	ATTR_RECORD *rootattr = 0, *allocattr = 0, *nameattr = 0, *bitmapattr = 0;
	DWORD vcn[2] = { 0 };

	for (;;){ // определение типов всех атрибутов записи
		mft_attr = mft_record_cursor;
		if (mft_attr[0].type == AT_END) break;
		if (mft_attr[0].type == AT_FILE_NAME) nameattr = mft_attr;
		if (mft_attr[0].type == AT_BITMAP) bitmapattr = mft_attr;
		if (mft_attr[0].type == AT_INDEX_ROOT){ rootattr = mft_attr; root = mft_record_cursor + mft_attr[0].r.value_offset; } // если IR, то получаем смещение тела IR относительно его заголовка
		if (mft_attr[0].type == AT_INDEX_ALLOCATION) { allocattr = mft_attr; }
		mft_record_cursor += mft_attr[0].length; // переход к следующему атрибуту
	}
	BYTE *bitmap = 0, *runlist = 0;
	DWORD bitmaplen = 0;

	if (rootattr == 0) { SetLastError(ERROR_PATH_NOT_FOUND); return 0; } // Если не нашли IR, то это не корневой каталог
	if (allocattr){ mft_record_cursor = allocattr; runlist = mft_record_cursor + allocattr[0].nr.mapping_pairs_offset; } // если есть IA, то находим смещение его списка отрезков
	if (bitmapattr){ mft_record_cursor = bitmapattr; bitmap = mft_record_cursor + bitmapattr[0].r.value_offset; bitmaplen = bitmapattr[0].r.value_length; } // для Bitmap находим смещение тела относительно заголовка атрибута и длину тела

	FindInIndexRoot(context, root, filename, namelen, result); // поиск в IR корневого каталога номера записи (в виде структуры) файлового объекта по имени, начиная со смещения тела атрибута IR (относительно начала записи)
	if (result[0].indexHigh != -1 && result[0].indexLow != -1) return 1; // если нашли в IR, то всё, если нет - поиск в IA

	if (allocattr) { // поиск в IA корневого каталога номера записи (в виде структуры) файлового объекта по имени
		DWORD found = FindInIndexAllocation(context, allocattr, filename, namelen, bitmap, bitmaplen, result);
		return found;
	}
	return 0;
}

BOOL CALLBACK DllMain(HANDLE hModule, DWORD  Reason, LPVOID lpReserved){
	BYTE namebuf[24] = { 0 };
	DWORD i = 0, tid=0;
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}
int _cdecl main(int argc, char **argv){
	DWORD read = 0, index = 0, found = 0, inputlen = 0;
	MFT_REF reference = { 0 };
	WCHAR *buffer = 0;
	HANDLE consoleIn = 0;
	NTFS_VOLUME_CONTEXT *context[26] = { 0 };
	DWORD clusters1[24] = { 0 };
	DWORD *clusters = clusters1;
	DWORD atrecords[20] = { 0 };

	consoleOut = GetStdHandle(STD_OUTPUT_HANDLE); consoleIn = GetStdHandle(STD_INPUT_HANDLE);
	buffer = VirtualAlloc(0, 1 << 15, MEM_COMMIT, PAGE_READWRITE);

	WriteConsoleW(consoleOut, L"Enter path to find in NTFS\r\n", sizeof(L"Enter path to find in NTFS\r\n") / 2 - 1, &read, NULL);
	ReadConsoleW(consoleIn, buffer, 1 << 12, &inputlen, NULL);
	buffer[inputlen - 2] = 0;
	WCHAR letter = buffer[0];
	letter |= 32;

	if (letter < 'a' || letter > 'z') {	wprintf(L"Invalid path\r\n"); return 0;	}
	index = letter - 'a';
	found = Get_MFT_EntryForPath(context + index, buffer, inputlen - 2, &reference);	// номер записи
	inputlen = 20;

	if (found == 0){ wprintf(L"File not found\r\n"); }
	else{ // если есть номер записи
		read = 8;
		wprintf(L"File found at %04x%08x\r\n", reference.indexHigh, reference.indexLow);
		
		found = GetFileClusters(context[index], reference, &read, clusters); // поиск кластеров
		if (found == 0){
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) clusters = malloc(read * 3 * 4);
			found = GetFileClusters(context[index], reference, &read, clusters);
		}
		if (found){ // если нашли кластеры
			DWORD written = 0;
			wprintf(L"File fragments:\r\n");
			for (DWORD i = 0, j = 0; i < read; i++, j += 3){
				WCHAR *fmt = L"%x%08x";
				if (clusters[j + 1] == 0) fmt = L"%x%x";
				wprintf(L"Start cluster : ");
				wprintf(fmt, clusters[j + 1], clusters[j]);
				wprintf(L", length: %x\r\n", clusters[j + 2]);
			}
		}
	}
	wprintf(L"Press enter to exit");
	ReadConsoleW(consoleIn, buffer, 4, &read, NULL);

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}
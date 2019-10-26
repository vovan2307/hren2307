unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs;

type
  TForm1 = class(TForm)
  private
    { Private declarations }
  public
    { Public declarations }
  end;
  mass = array of dword;

  MFT_REF = Packed Record
    indexLow: dword;
    indexHigh: word;
    ordinal: word;
  end;

  FILE_FRAGMENT = Packed Record
      lcnLow: dword;
      lcnHigh: dword;
      count: dword;
  end;
  PMFT_RECORD=^MFT_RECORD;
  PFILE_FRAGMENT=^FILE_FRAGMENT;
  PPointer = ^pointer;

var
  Form1: TForm1;
  s:pwidechar;
  cindex: DWORD;// index of disk context
  found:integer;
  exMFT_REF:MFT_REF;
  fragments:PFILE_FRAGMENT;

  buflen:DWORD;
  mass:PDWORD;
  pcontext:array[0..25] of pointer;

function Get_MFT_EntryForPath (pcontext: PPointer; path : PWideChar; pathlen:Integer; found1: PMFT_RECORD) : DWord; stdcall; external 'ntfs.dll';
function GetFileClusters(context:pointer; fileref:MFT_REF; buflen:PDWORD; lcn_len_pairs:PDWORD):DWord; stdcall; external 'ntfs.dll';
function FreeNTFSContext(context:pointer;):DWord; stdcall; external 'ntfs.dll';

implementation

{$R *.dfm}
begin
buflen:=8;
s:='G:\bigg.txt';
cindex=DWORD(s[0]);
cindex:=cindex or 32;
cindex -= $61; {cindex=lowcase(s[0])-'a'}

if (cindex<26) then begin
GetMem(mass, sizeof(DWORD)*3*8); // Выделить память под 8 отрезков
// Передать функции адрес pcontext[cindex]
found:=Get_MFT_EntryForPath (@pcontext[cindex], s, -1, @exMFT_REF);
showmessage('Номер записи = ' + IntToHex(exMFT_REF.indexLow));

found:=GetFileClusters(pcontext[cindex],exMFT_REF,@buflen,mass);
if (found=0 and GetLastError()=ERROR_INSUFFICIENT_BUFFER) then begin
	FreeMem(mass);
	GetMem(mass, sizeof(DWORD)*3*buflen);
	found:=GetFileClusters(pcontext[cindex],exMFT_REF,@buflen,mass);
end;
fragments:=PFILE_FRAGMENT(mass);

showmessage('Отрезки: количество= '+inttostr(buflen)+chr(13)
		+'смещение первого = ' + IntToHex(mass[1],1) + IntToHex(mass[0],1) + chr(13)
        + 'длина в кластерах = ' + IntToHex(mass[2],1) );
FreeMem(mass);
end;

end.

// PTPS-Generate-License-Key.cpp : Defines the entry point for the application.
//

/*

PTPS 5.7 or ealier (VS 2012)
CStringP
  <&const CStringP::`vftable'> @ RSI
  +0 // vtable
  +8 // m_data

PTPS 5.8 or later (VS 2019)
CStringP
  <&const CStringP::`vftable'> @ R15
  +0 // vtable
  +8 // m_data

*/

#include <vu>
using namespace vu;
using namespace std;

#define require(cond, msg) if (!(cond)) throw string(msg);

tstring run_and_get_license_key(const tstring& file_path)
{
  tstring result;

  try
  {
    tstring file_name = extract_file_name(file_path);
    tstring file_cdir = extract_file_directory(file_path);
    PROCESS_INFORMATION pi = { 0 };

    // create the process
    Process process;
    process.create(file_path, file_cdir, ts(""), NORMAL_PRIORITY_CLASS, false, &pi);
    require(process.ready(), "create process failed");
    WaitForInputIdle(pi.hProcess, INFINITE); // wait for process fully loaded in virtual memory

    // find the address that available to get key
    std::vector<size_t> addresses;
    tstring version = ts("58");
    tstring pattern = ts("48 8B 4C 24 28 48 85 C9 74 43 48 8B 54 24 ?? 48 2B D1 48 8B C1 48 81 FA 00 10 00 00 72 1C");
    process.scan_memory(addresses, pattern, file_name, true, MEM_COMMIT, MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE);
    if (addresses.empty())
    {
      version = ts("57");
      pattern = ts("74 09 48 8B CB E8 ?? ?? ?? ?? 90 48 85 FF 74 08 48 8B CF");
      process.scan_memory(addresses, pattern, file_name, true, MEM_COMMIT, MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE);
    }
    require(!addresses.empty(), "find address failed");
    auto address = addresses.front();

    // set break-point at the found address
    vu::byte bp[2] = { 0xEB, 0xFE }, bk[2] = { 0 };
    bool status = true;
    status &= process.read_memory(address, bk, sizeof(bk));
    status &= process.write_memory(address, bp, sizeof(bp), true);
    require(status, "set break-point failed");
    msg_box(ts("Do the following steps :\n\n1. Select features (optional).\n2. Press 'Apply' button.\n3. Close this message box."));

    // get context registers of the main thread
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    // get generated license key from memory in the created process
    ulongptr CStringP_object = version == ts("58") ? ctx.R15 : ctx.Rsi;
    ulongptr CStringP_m_data = CStringP_object + 8;
    tchar key[32 + 1] = { 0 };
    read_memory_ex(arch::x64, pi.hProcess, LPCVOID(CStringP_m_data), key, sizeof(key), true, 1, 0);
    key[32] = ts('\x00');
    result.assign(key);

    // remove break-point at the found address
    status &= process.write_memory(address, bk, sizeof(bk), true);
    require(status, "remove break-point failed");

    // termiate process after finished
    // TerminateProcess(pi.hProcess, 0);
  }
  catch (string error)
  {
    #ifdef _UNICODE
    result = to_string_W(error);
    #else
    result = error;
    #endif
  }

  return result;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
  Picker picker;
  tstring file_path = ts("LicenseManager.exe");
  const auto file_filter = ts("Executable File (.exe)\0*.exe\0");
  if (!picker.choose_file(Picker::action_type::open, file_path, ts(""), file_filter)) return 0;

  auto key = run_and_get_license_key(file_path);

  Sleep(1000); // waiting for the invalid message box shown

  InputDialog dlg(ts("Generated License Key"), nullptr, false, key);
  dlg.do_modal();

  return 0;
}

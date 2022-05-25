// PTPS-Generate-License-Key.cpp : Defines the entry point for the application.
//

/*

Panther TPS 5.7 or ealier (VS 2012)
74 09 48 8B CB E8 ?? ?? ?? ?? 90 48 85 FF 74 08 48 8B CF
RSI = 000000000014B500     <&const CStringP::`vftable'>
000000000014B500  00007FFABAF13688  .6��...  panthercommon.??_7CStringP@@6B@         // vtable
000000000014B508  00000000063FF680  .�?.....  L"3B0BC207F8151B231A166492EE99C941"     // m_data

Panther TPS 5.8 or later (VS 2019)
74 43 48 8B 54 24 ?? 48 2B D1 48 8B C1 48 81 FA 00 10 00 00 72 1C
R15 : 000000000014C9E8     <&const CStringP::`vftable'>
000000000014C9E8  00007FFAB312D550  P�.��...  panthercommon.const CStringP::`vftable' // vtable
000000000014C9F0  00000000104E58A0  �XN.....  L"3B0BC207F8151B231A166492EE99C941"     // m_data

*/

#include <vu>
using namespace vu;
using namespace std;

#define require(cond, msg) if (!(cond)) throw string(msg);

ulongptr scan_process_region_memories_to_find_address(Process& process, const tstring& pattern)
{
  const auto exe = process.get_module_information();

  for (auto& e : process.get_memories(MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE_READ))
  {
    if (e.BaseAddress < exe.modBaseAddr || e.BaseAddress > exe.modBaseAddr + exe.modBaseSize)
    {
      continue;
    }

    Buffer block;
    block.resize(e.RegionSize);
    bool ret = process.read_memory(ulongptr(e.BaseAddress), block);
    require(ret, "read region memory failed");

    auto offsets = find_pattern(block, pattern, true);
    if (!offsets.empty())
    {
      return ulongptr(e.BaseAddress) + offsets.front();
    }
  }

  return -1;
}

tstring run_and_get_license_key(tstring file_path)
{
  tstring result;

  try
  {
    tstring file_dir = extract_file_directory(file_path);
    PROCESS_INFORMATION pi = { 0 };

    // create the process
    Process process;
    process.create(file_path, extract_file_directory(file_path), ts(""), NORMAL_PRIORITY_CLASS, false, &pi);
    require(process.ready(), "create process failed");
    WaitForInputIdle(pi.hProcess, INFINITE); // wait for process fully loaded in virtual memory

    // find the address that available to get key
    tstring version = ts("58");
    tstring pattern = ts("74 43 48 8B 54 24 ?? 48 2B D1 48 8B C1 48 81 FA 00 10 00 00 72 1C");
    auto address = scan_process_region_memories_to_find_address(process, pattern);
    if (address == -1)
    {
      version = ts("57");
      pattern = ts("74 09 48 8B CB E8 ?? ?? ?? ?? 90 48 85 FF 74 08 48 8B CF");
      address = scan_process_region_memories_to_find_address(process, pattern);
    }
    require(address != -1, "find address failed");

    // set break-point at the found address
    vu::byte bp[2] = { 0xEB, 0xFE }; // jmp rip
    auto status = process.write_memory(address, bp, sizeof(bp), true);
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

    // termiate process after finished
    TerminateProcess(pi.hProcess, 0);
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
  InputDialog dlg(ts("Generated License Key"), nullptr, false, key);
  dlg.do_modal();

  return 0;
}
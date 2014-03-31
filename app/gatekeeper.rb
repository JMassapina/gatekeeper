#!/usr/bin/env ruby

require 'rubygems'
require 'lockfile'
require 'cisco'
require 'aws-sdk'
require 'net/https'
require 'addressable/uri'
require 'uri'
require 'hashery'
require 'logger'
require 'logger/colors' if STDOUT.tty?
require 'optparse'
require 'pp'
require 'json'

OPTIONS = OpenStruct.new
OPTIONS.config_file = '/etc/gatekeeper.conf.yml'

OptionParser.new do |opts|
  opts.banner = 'Usage: gatekeeper.rb [options]'
  opts.on('--conf configfile', String, 'Config file') do |configfile|
    OPTIONS.config_file = configfile
  end
end.parse!

CONFIG = YAML.load(File.read(OPTIONS.config_file))

# ----- OVERRIDES -------------------------------------------------------------------
# Cisco devices don't implement the SSH2 protocol correctly; ignore certain errors

module Net; module SSH; module Transport; module PacketStream
  def next_packet(mode=:nonblock)
      case mode
      when :nonblock then
        if available_for_read?
          if fill <= 0
#           raise Net::SSH::Disconnect, "connection closed by remote host"
          end
        end
        poll_next_packet

      when :block then
        loop do
          packet = poll_next_packet
          return packet if packet

          loop do
            result = Net::SSH::Compat.io_select([self]) or next
            break if result.first.any?
          end

          if fill <= 0
#           raise Net::SSH::Disconnect, "connection closed by remote host"
          end
        end

      else
        raise ArgumentError, "expected :block or :nonblock, got #{mode.inspect}"
      end
  end
end; end; end; end;

# ------------------------------------------------------------------------------------

LOGGER = Logger.new(STDOUT)
LOGGER.level = (STDOUT.tty? ? Logger::DEBUG : Logger::ERROR)
attempts_left = CONFIG['max_attempts']

aws_hosts = []
rules = []
groupdata = {}

def read_cache
	begin
		cache_hosts = Marshal.load(File.read(CONFIG['cache_file']))
		LOGGER.debug('cache contains %u entries' % cache_hosts.count)
	rescue
		LOGGER.warn('cache file not found - creating a new one')
		cache_hosts = []
	end
	return cache_hosts
end

def get_sessions(asa)
	attempts_left = CONFIG['max_attempts']
	begin
		output = asa.run do |x|
			x.enable(CONFIG['device_enable'])
			# Don't use paging
			x.cmd('terminal pager 0')
			# Get a fully copy of the session database to show logged-in users
			x.cmd('show vpn-sessiondb full remote')
		end
	rescue Net::SSH::Disconnect => e
		attempts_left -= 1
		if attempts_left > 0
			LOGGER.warn('abruptly disconnected from device, reconnecting (attempt %u of %u)'  % [ (CONFIG['max_attempts'] - attempts_left), CONFIG['max_attempts'] ])
			LOGGER.debug('ssh: %s' % e.message)
			retry
		else
			LOGGER.fatal('too many connection failures - aborting')
			exit
		end
	rescue Cisco::CiscoError => e
		LOGGER.fatal('error from device: %s' % e.message)
		exit
	rescue Timeout::Error => e
		attempts_left -= 1
		if attempts_left > 0
			LOGGER.warn('execution expired, retrying (attempt %u of %u)' % [ (CONFIG['max_attempts'] - attempts_left), CONFIG['max_attempts'] ] )
			LOGGER.debug('ssh execution expired: %s' % e.message)
			retry
		else
			LOGGER.fatal('unable to get object group and too many failures, aborting' % CONFIG['max_attempts'])
			exit
		end
	end

	begin
		sessions = output[5].split("\n").reject{ |x| x.empty? }.drop(3)
		b = {}

		# Efficient way to grab usernames and IPs from the ASA's output.
		sessions.collect { |s| Hash[ *s.scan(/\s+([a-zA-Z ]+): ([a-zA-Z0-9.\-_ ]+) [\|]+/).flatten ] }.each { |a| b[a['Username']] = a }
		return b
	rescue
		LOGGER.fatal('could not read object list from device')
		exit
	end
end

def hipchat_notify_success(device)
	options = {
			:room_id => CONFIG['hipchat_room_id'],
			:from => 'Gatekeeper',
			:message_format => 'html',
			:color => 'green',
			:message => 'Updated object-group for AWS instances deployed to %s' % device
	}

	query = Addressable::URI.new
	query.query_values = options
	uri = URI.parse(HIPCHAT_URI)

	if CONFIG['hipchat_enabled']
		LOGGER.info('posting to hipchat' % uri.request_uri)
		http = Net::HTTP.new(uri.host, uri.port)
		http.use_ssl = true
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		http.start do |this|
			response = this.request_post(uri.request_uri, query.query)
			LOGGER.warn('could not send notification to hipchat') unless response.kind_of? Net::HTTPOK
			LOGGER.debug(response)
		end
	end
end

# ----- MAIN -----

lockfile = Lockfile.new(CONFIG['lock_file'], :retries => 1)
begin
	LOGGER.debug('grabbing lock')
	lockfile.lock

	asa = Cisco::Base.new( :directargs => [ CONFIG['device_hostname'], CONFIG['device_user'], {
		:password => CONFIG['device_password'],
		:auth_methods => ['password'],
		:verbose => :warn,
		:timeout => 10
	} ], :transport => 'ssh')

	LOGGER.info('connected to %s, getting configuration' % CONFIG['device_hostname'])

	active_users = get_sessions(asa)

	endpoint = URI.parse(CONFIG['server_endpoint'])
	request = Net::HTTP::Put.new(endpoint.path, initheader = { 'Content-Type' => 'text/plain'} )
	request.body = active_users.to_json
	response = Net::HTTP.new(endpoint.host, endpoint.port).start { |http| http.request(request) }

	puts response.body

	LOGGER.info('operation complete')

rescue Lockfile::MaxTriesLockError
	LOGGER.warn('could not acquire lock (%s)' % CONFIG['lock_file'])
rescue Lockfile::StolenLockError
	LOGGER.fatal('lock was stolen, aborting (%s)' % CONFIG['lock_file'])
ensure
	exit unless lockfile.locked?
	LOGGER.debug('releasing lock')
	lockfile.unlock
end


# encoding: utf-8
require "logstash/filters/base"
require "virustotalx"

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Virustotalthree < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "virustotalthree"

  # Your VirusTotal API Key
  config :apikey, :validate => :string, :required => true

  # For filed containing the item to lookup. This can point to a field ontaining a File Hash or URL
  config :field, :validate => :string, :required => true

  # Lookup type
  config :lookup_type, :validate => :string, :required => true

  # Where you want the data to be placed
  config :target, :validate => :string, :default => "virustotalthree"

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    begin
      @logger.warn("LSFVTL: ", :apikey => @apikey)
      # when given nothing, it tries to load your API key from ENV["VIRUSTOTAL_API_KEY"]
      api = VirusTotal::API.new(key: @apikey)
      if @lookup_type == "hash"
        vt_report = api.file.get(event.get(@field))
      elsif @lookup_type == "domain"
        vt_report = api.domain.get(event.get(@field))
      elsif @lookup_type == "url"
        vt_report = api.url.get(event.get(@field))
      elsif @lookup_type == "ip"
        vt_report = api.ip_address.get(event.get(@field))
      end
      event.set(@target, vt_report)
      # filter_matched should go in the last line of our successful code
      filter_matched(event)
    rescue => e
      @logger.warn("Error getting virus total lookup", :field => event.get(@field), :exception => e)
    end
  end # def filter
end # class LogStash::Filters::Virustotalthree

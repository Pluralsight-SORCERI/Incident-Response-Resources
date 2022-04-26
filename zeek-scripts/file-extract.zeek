redef PacketFilter::default_capture_filter="port 445";

event file_new(f: fa_file)
{
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
	Files::add_analyzer(f, Files::ANALYZER_MD5);
}

#n
1i\
static const struct {\
	QmiProtocolError code;\
	const char *text;\
} qmi_errors[] = {

/@QMI_.*_ERROR/s/^.*@\(.*\): \(.*\)\.$/	{ \1, "\2" },/p

$a\
};

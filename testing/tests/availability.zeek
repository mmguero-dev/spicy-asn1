# @TEST-DOC: Check that the ASN.1 analyzer is available.
#
@TEST-EXEC: zeek -NN | grep -Eqi 'ANALYZER_SPICY_ASN1'

type AcmeCertAuthority struct {
    processor *CertProcessor
}

func (ca *AcmeCertAuthority) ProvisionCert(cert *Certificate) (CertData, error) {

}


func (ca *AcmeCertAuthority) RenewCert(cert *Certificate, certDetails *CertData) (CertData, error) {

}

"""
Cross-industry compliance attestations.

MACE maps its native controls to every major regulatory framework so the
same evidence stream serves whichever auditor is in the room.

Frameworks covered (frameworks.py):

  Cross-cutting               NIST 800-53 rev5, NIST CSF 2.0, ISO 27001:2022,
                              ISO 27017, ISO 27018, SOC 2 Type II
  US Federal / public-sector  FedRAMP Moderate, FedRAMP High,
                              DoD CMMC 2.0 L1/L2/L3, DHS CDM,
                              CJIS Security Policy, FIPS 140-3, IRS Pub 1075,
                              StateRAMP
  US Industry                 PCI-DSS 4.0, HIPAA / HITRUST CSF,
                              FFIEC CAT + NCUA Part 749, SOX ITGC,
                              NERC CIP v7, TSA Pipeline SD-02C,
                              FAA / DOT cyber directives, FCC CPNI,
                              FERPA, FINRA Rule 4370
  EU / UK                     GDPR Art. 32, NIS2, DORA, UK Cyber Essentials,
                              UK Cyber Essentials Plus
  India                       DPDP Act 2023, CERT-In 6-hour directive,
                              RBI Cyber Framework, SEBI System Audit,
                              MeitY SDLC, IRDAI ITGC
  UAE / GCC                   NESA UAE IAS, SAMA Cyber, SBM SAR 2.0,
                              Saudi NCA ECC, Qatar NIA Policy,
                              Oman OCC Cyber, Dubai DESC
  Other regions               Canada PIPEDA + OSFI B-13, Singapore CSA,
                              Australia ESSENTIAL 8, Japan METI Cybersecurity
  Industry-vertical            IATA Cyber Security Toolkit (airlines),
                              GLBA Safeguards (US banking), HHS 405(d)
                              (healthcare), AICPA Trust Services Criteria,
                              MITRE ATT&CK Defender (D3FEND), CWE Top 25

industries.py groups them so a buyer can select "Healthcare" or "Airline"
and immediately see the relevant attestations and which MACE controls
satisfy them.
"""
from .frameworks import FRAMEWORK_CATALOG, ControlMapping, framework_status
from .industries import INDUSTRY_PROFILES, profile_for_industry

__all__ = ["FRAMEWORK_CATALOG", "ControlMapping", "framework_status",
            "INDUSTRY_PROFILES", "profile_for_industry"]

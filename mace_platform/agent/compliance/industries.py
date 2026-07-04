"""
Industry profiles — which frameworks matter for which kind of customer.

A buyer self-selects their industry and immediately sees:
  • the frameworks that apply to them,
  • the MACE modules that satisfy each one,
  • the percentage of controls already evidenced by the current fleet.

This is what makes a sales call easy: "for an airline you specifically
need IATA Cyber Security Toolkit + FAA AC 119-1 + GDPR Art.32 + TSA SD-02C
and MACE evidences all of those out of the box."
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class IndustryProfile:
    name: str
    sector_id: str
    required_frameworks: List[str]
    notable_buyers: List[str]
    notes: str


INDUSTRY_PROFILES: Dict[str, IndustryProfile] = {
    "airline": IndustryProfile("Airlines & Aviation", "aviation",
        ["iata_toolkit", "faa_cyber", "tsa_sd02c", "gdpr", "pcidss_4", "iso27001_2022"],
        ["Delta", "Lufthansa", "Emirates", "IndiGo", "Air India", "British Airways"],
        "TSA Pipeline SD-02C also applies to airline operations; FAA AC 119-1 covers aircraft systems."),
    "bank_us": IndustryProfile("US Banking & Financial Services", "banking",
        ["ffiec_cat", "pcidss_4", "sox_itgc", "gdpr", "iso27001_2022", "soc2_typeii",
         "fedramp_moderate"],
        ["JPMC", "BofA", "Wells Fargo", "Citi", "Goldman", "Capital One"],
        "FFIEC CAT maturity 5 + PCI-DSS 4.0 baseline. SOX ITGC applies to publicly traded banks."),
    "bank_india": IndustryProfile("Indian Banking", "banking_in",
        ["rbi_cyber", "cert_in_6hr", "india_dpdp", "pcidss_4", "iso27001_2022"],
        ["HDFC Bank", "ICICI", "SBI", "Kotak", "Axis"],
        "RBI Cyber Framework is mandatory; CERT-In 6-hour rule applies to all licensed entities."),
    "bank_uae": IndustryProfile("UAE Banking", "banking_ae",
        ["uae_nesa", "pcidss_4", "iso27001_2022", "soc2_typeii"],
        ["Emirates NBD", "FAB", "ADCB", "Mashreq", "ENBD"],
        "Central Bank UAE Information Security Standard mirrors NESA Tier 4."),
    "healthcare": IndustryProfile("Healthcare & Hospitals", "healthcare",
        ["hipaa", "hhs_405d", "iso27001_2022", "soc2_typeii", "pcidss_4"],
        ["Mayo Clinic", "Cleveland Clinic", "Kaiser", "Apollo Hospitals", "Sheikh Khalifa Medical City"],
        "HHS 405(d) covers medical-device cybersecurity; HITRUST CSF is increasingly required for partners."),
    "social_media": IndustryProfile("Social Media & Consumer Internet", "consumer_internet",
        ["gdpr", "ccpa_cpra", "india_dpdp", "soc2_typeii", "iso27001_2022"],
        ["Meta", "X", "TikTok", "Reddit", "Pinterest", "Snap"],
        "Privacy regulations dominate; PCI-DSS only if direct payment processing."),
    "energy_utility": IndustryProfile("Energy & Utilities", "energy",
        ["nerc_cip", "tsa_sd02c", "iso27001_2022", "fedramp_moderate"],
        ["Duke Energy", "Tata Power", "PG&E", "EDF", "ADNOC", "Saudi Aramco"],
        "NERC CIP for bulk-electric; TSA SD-02C extends to pipelines."),
    "telecom": IndustryProfile("Telecommunications", "telecom",
        ["fcc_cpni", "iso27001_2022", "gdpr", "soc2_typeii", "india_dpdp", "uae_nesa"],
        ["Verizon", "AT&T", "Jio", "Airtel", "Etisalat (e&)", "du"],
        "TRAI (India) + FCC CPNI (US) + GDPR (EU) all apply for subscriber-data handling."),
    "gov_federal": IndustryProfile("US Federal Government", "gov_fed",
        ["fedramp_moderate", "dhs_cdm", "cmmc_l2", "fedramp_high", "fisma"],
        ["DOD", "DHS", "GSA", "VA", "HHS", "Treasury"],
        "Requires FedRAMP Moderate minimum; DHS CDM compatibility is a competitive must."),
    "gov_dod": IndustryProfile("US Department of Defense", "gov_dod",
        ["cmmc_l2", "fedramp_high", "dhs_cdm", "iso27001_2022"],
        ["USAF", "Army", "Navy", "USSF", "USCG", "JFHQ-DODIN"],
        "CMMC 2.0 L2 minimum for CUI; IL-5 enclaves require additional CSfC layering."),
    "gov_state": IndustryProfile("US State & Local Government", "gov_state",
        ["fedramp_moderate", "cjis", "stateramp", "iso27001_2022"],
        ["California", "Texas", "New York", "Florida", "Illinois"],
        "StateRAMP increasingly replaces individual state ATO processes; CJIS for law enforcement."),
    "gov_india": IndustryProfile("India Government / CII", "gov_in",
        ["cert_in_6hr", "india_dpdp", "iso27001_2022", "meity_sdlc"],
        ["NIC", "UIDAI", "GSTN", "Indian Railways", "BSNL"],
        "MeitY guidelines + CERT-In directive + DPDP overlap; jurisdiction-aware MACE profile applies."),
    "gov_uae": IndustryProfile("UAE Government", "gov_ae",
        ["uae_nesa", "iso27001_2022", "soc2_typeii"],
        ["Smart Dubai", "TDRA", "Dubai Police", "Federal Authority for Identity"],
        "NESA UAE IAS Tier 4 is the bar; data-residency in country is mandatory."),
    "retail_ecommerce": IndustryProfile("Retail & E-Commerce", "retail",
        ["pcidss_4", "soc2_typeii", "gdpr", "ccpa_cpra", "iso27001_2022"],
        ["Walmart", "Amazon", "Reliance Retail", "Carrefour", "Tesco"],
        "PCI-DSS 4.0 is mandatory; CCPA/GDPR for customer data; supply-chain DLP critical."),
    "manufacturing": IndustryProfile("Manufacturing & Industrial", "manufacturing",
        ["iec_62443", "iso27001_2022", "nis2", "cmmc_l2"],
        ["Boeing", "Lockheed", "Tata Steel", "Hyundai", "Siemens"],
        "IEC 62443 for OT/ICS; CMMC L2 if any defence subcontracting."),
    "education": IndustryProfile("Higher Education", "education",
        ["ferpa", "soc2_typeii", "iso27001_2022"],
        ["MIT", "Stanford", "IIT Bombay", "Oxford", "Cambridge"],
        "FERPA for student records; CSC2 / Higher-ed Cyber Maturity Model."),
    "saas_b2b": IndustryProfile("SaaS / B2B Software", "saas",
        ["soc2_typeii", "iso27001_2022", "gdpr", "ccpa_cpra"],
        ["Atlassian", "ServiceNow", "Workday", "Datadog", "Snowflake"],
        "SOC 2 Type II is table stakes; ISO 27001 increasingly required for European buyers."),
}


def profile_for_industry(industry: str) -> IndustryProfile | None:
    return INDUSTRY_PROFILES.get(industry)

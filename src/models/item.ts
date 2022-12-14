import axios from "axios";
import dns from "dns/promises";
import { Color, log } from "../utils";
import { App } from "./app";

export interface ItemCreationPayload {
  dnsName: string;
  domains: Set<string>;
  domain: string;
  queriedDomain: string;
  issuanceDate: Date;
}

export class Item {
  static dnsNames: Set<string> = new Set();

  public linkedDomains: Set<string>;
  public domain: string;
  public dnsName: string;
  public queriedDomain: string;
  public lastIssuanceDate: Date;
  public httpStatus?: number;
  public resolvedIpAddress?: string;

  constructor(payload: ItemCreationPayload, app: App) {
    const { dnsName, domains, queriedDomain, issuanceDate, domain } = payload;
    const {
      todoDomains,
      doneDomains,
      options: { domainDenyList, wordDenyList },
    } = app;

    if (dnsName.split(" ").length > 1) {
      throw new Error("DNS name with whitespace");
    }

    if (Item.dnsNames.has(dnsName)) {
      // update already found report last issuance date
      const item = app.items.find((r) => r.dnsName === dnsName);
      if (!item) {
        throw new Error("DNS name already done but not found");
      }
      if (item && item.lastIssuanceDate < issuanceDate) {
        item.lastIssuanceDate = issuanceDate;
      }
      for (const d of payload.domains) {
        item.linkedDomains.add(d);
      }
      throw new Error("DNS name already done");
    }
    Item.dnsNames.add(dnsName);

    const wordDenyListRegex =
      wordDenyList.length > 0
        ? RegExp(".*(" + wordDenyList.join("|") + ").*", "i")
        : null;

    if (domainDenyList.includes(domain) || wordDenyListRegex?.test(domain)) {
      throw new Error("Domain on deny list");
    }

    if (
      !todoDomains.has(domain) &&
      !doneDomains.has(domain) &&
      !domainDenyList.includes(domain)
    ) {
      log("New domain found : " + domain, Color.FgBlue);
      app.todoDomains.add(domain);
    }

    if (wordDenyListRegex?.test(dnsName)) {
      throw new Error("DNS name contains a word on deny list");
    }

    this.domain = domain;
    this.dnsName = dnsName;
    this.queriedDomain = queriedDomain;
    this.linkedDomains = domains;
    this.lastIssuanceDate = issuanceDate;
  }

  async getHttpStatus(): Promise<number | undefined> {
    try {
      if (this.dnsName.includes("*")) return;
      const op = async (protocol: "http" | "https") => {
        try {
          return await axios.get(`${protocol}://${this.dnsName}`, {
            timeout: 5000,
          });
        } catch (err) {
          return undefined;
        }
      };
      const [httpResponse, httpsResponse] = await Promise.all([
        op("http"),
        op("https"),
      ]);
      this.httpStatus = httpsResponse?.status ?? httpResponse?.status;
      return this.httpStatus;
    } catch (err) {}
  }
  async resolve(): Promise<string | undefined> {
    try {
      if (this.dnsName.includes("*")) return;
      const response = await dns.lookup(this.dnsName);
      this.resolvedIpAddress = response.address;
      return this.resolvedIpAddress;
    } catch (err) {}
  }
}

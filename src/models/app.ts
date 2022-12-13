import axios, { AxiosResponse } from "axios";
import { Command, Option } from "commander";
import stringify from "csv-stringify/lib/sync";
import { join } from "path";
import psl from "psl";
import { Color, log, output, sleepFor } from "../utils";
import { Item } from "./item";
import { renderFile } from "pug";
const pkg = require("./../../package.json");

export interface AppOptions {
  maxDepthLevel: number;
  outputFormat: OutputFormat;
  onlyResolved: boolean;
  resolve: boolean;
  domainDenyList: string[];
  wordDenyList: string[];
  initialTarget: string;
}

export enum OutputFormat {
  json = "json",
  csv = "csv",
  html = "html",
  none = "none",
}

export type CrtShItem = {
  issuer_ca_id: string,
  issuer_name: string,
  common_name: string,
  name_value: string,
  id: number,
  entry_timestamp: Date,
  not_before: Date,
  not_after: Date,
  serial_number: string,
}

export type CrtShItemList = CrtShItem[]

export class App {
  static readonly HEADER =
    `               _   
              | |  
 _ __ ___ _ __| |_ 
| '__/ __| '__| __|
| | | (__| |  | |_ 
|_|  \\___|_|   \\__|
`;
  static readonly VERSION = pkg.version;
  static readonly DEFAULT_DEPTH_LEVEL = 0;
  static readonly DEFAULT_OUTPUT_FORMAT = OutputFormat.html;
  static readonly CRT_SH_BASE_URL = "https://crt.sh";

  public items: Item[] = [];
  public todoDomains: Set<string> = new Set();
  public doneDomains: Set<string> = new Set();

  public options: AppOptions = {
    maxDepthLevel: 0,
    outputFormat: OutputFormat.html,
    onlyResolved: false,
    domainDenyList: [],
    wordDenyList: [],
    resolve: false,
    initialTarget: "",
  };

  constructor() {
    const program = new Command();
    program
      .name("rcrt")
      .usage("-t domain.tld -r -d google.com google.fr -o html > report.html")
      .description(
        "Retrieves SSL/TLS certificate reports information from crt.sh for a given domain."
      )
      .version(App.VERSION, "-v, --version", "output the current version")
      .helpOption("-h, --help", "output usage information")
      .requiredOption("-t, --target [domain]", "set the target domain")
      .addOption(
        new Option(
          "-l, --depth-level <level>",
          "set the depth level for the recursive domain discovery"
        ).default("0")
      )
      .addOption(
        new Option(
          "-o, --output-format [format]",
          "set the format for the report sent to stdout"
        )
          .choices([
            OutputFormat.csv,
            OutputFormat.html,
            OutputFormat.json,
            OutputFormat.none,
          ])
          .default("none")
      )
      .addOption(
        new Option("-R, --only-resolved", "only output resolved domains")
      )
      .addOption(
        new Option("-r, --resolve", "perform DNS and HTTP/S checks on domains")
      )
      .addOption(
        new Option(
          "-d, --domain-deny-list [domain...]",
          "set the deny list for domains"
        )
      )
      .addOption(
        new Option(
          "-wd, --word-deny-list [word...]",
          "set the deny list for words"
        )
      )
      .parse();

    const opts = program.opts();

    log(App.HEADER);
    log(App.VERSION + "\n");

    let {
      depthLevel,
      outputFormat,
      onlyResolved,
      target,
      domainDenyList,
      wordDenyList,
      resolve,
    } = opts;

    const maxDepthLevel =
      depthLevel === undefined || isNaN(+depthLevel)
        ? App.DEFAULT_DEPTH_LEVEL
        : +depthLevel;

    if (!(outputFormat in OutputFormat)) {
      outputFormat = OutputFormat.none;
    }

    onlyResolved = !!onlyResolved;
    resolve = !!resolve;

    if (!Array.isArray(domainDenyList)) {
      domainDenyList = [];
    }

    if (!Array.isArray(wordDenyList)) {
      wordDenyList = [];
    }

    this.options = {
      maxDepthLevel,
      outputFormat,
      onlyResolved,
      domainDenyList,
      wordDenyList,
      resolve,
      initialTarget: target.toLowerCase(),
    };
  }

  async getCertificateRecords(
    target: string = this.options.initialTarget,
    depthLevel: number = 0
  ): Promise<void> {
    const { maxDepthLevel } = this.options;

    this.doneDomains.add(target);

    function parseCrtShResponse(res: AxiosResponse): CrtShItem[] {
      let rawData = res.data as CrtShItem[];
      const data = rawData;
      return data;
    }

    log(
      `Start processing : ${target}`,
      Color.FgCyan
    );

    let certs: CrtShItemList | null = null
    let attempt = 0
    let retrieved = false
    while (attempt < 10 && !retrieved) {
      try {
        certs = parseCrtShResponse(await axios.get(App.CRT_SH_BASE_URL + `/?q=${target}&output=json`))
        retrieved = true
      } catch (err) {
        attempt++
        await sleepFor(2000)
      }
    }
    if (!certs || !Array.isArray(certs)) {
      return
    }

    const promises = []
    let j = 0;
    for (let i = 0; i < certs.length; i++) {
      const handleCertificateRecord = async (
        cert: CrtShItem,
      ) => {
        try {
          const dnsNamesWithDomain = [];
          const domains: Set<string> = new Set();

          const dnsNames = cert.name_value.split("\n")
          dnsNames.push(cert.common_name)

          for (const dnsName of dnsNames) {
            if (!dnsName) continue;
            const domain = psl.get(dnsName)?.toLowerCase();
            if (!domain) continue;
            domains.add(domain);
            dnsNamesWithDomain.push({
              domain,
              dnsName,
            });
          }

          for (const { domain, dnsName } of dnsNamesWithDomain) {
            const item = new Item(
              {
                dnsName,
                domain,
                queriedDomain: target,
                issuanceDate: new Date(cert.not_before),
                domains,
              },
              this
            );
            const [ipAddr, httpStatus] = this.options.resolve
              ? await Promise.all([item.resolve(), item.getHttpStatus()])
              : [undefined, undefined];
            if (this.options.onlyResolved && !ipAddr) {
              continue;
            }
            const { resolvedIpAddress } = item;
            let color = resolvedIpAddress ? Color.FgYellow : Color.FgWhite;
            color = httpStatus === 200 ? Color.FgGreen : color;
            log(
              `${target} - ${j++}/${certs?.length} - ${dnsName} - ${resolvedIpAddress ? resolvedIpAddress : "not resolved"
              }`,
              color
            );
            this.items.push(item);
          }
        } catch (err) {
          return;
        }
      }
      promises.push(handleCertificateRecord(certs[i]))
    }

    await Promise.all(promises)

    if (depthLevel !== maxDepthLevel) {
      const domainPromises = [];
      const todoDomains = [...this.todoDomains];
      for (const domain of todoDomains) {
        if (this.doneDomains.has(domain)) continue;
        domainPromises.push(this.getCertificateRecords(domain, depthLevel + 1));
        this.doneDomains.add(domain);
        this.todoDomains.delete(domain);
      }
      await Promise.all(domainPromises);
    }
  }

  outputCertificateReports() {
    if (this.options.outputFormat === OutputFormat.none) {
      return;
    }
    log(`Outputting ${this.options.outputFormat} report to stdout.`, Color.FgCyan);
    switch (this.options.outputFormat) {
      case OutputFormat.json:
        output(JSON.stringify(this.items));
        break;
      case OutputFormat.csv:
        const columns: Array<{
          key: keyof Item;
          header: string;
        }> = [
            {
              key: "queriedDomain",
              header: "Queried domain",
            },
            {
              key: "linkedDomains",
              header: "Domains",
            },
            {
              key: "dnsName",
              header: "DNS name",
            },
            {
              key: "lastIssuanceDate",
              header: "Last certificate issuance date",
            },
            {
              key: "resolvedIpAddress",
              header: "Resolved IP address",
            },
            {
              key: "httpStatus",
              header: "HTTP/S status (GET)",
            },
          ];
        output(
          stringify(this.items, {
            columns,
            header: true,
            bom: true,
            record_delimiter: "windows",
            cast: {
              date(value) {
                return value.toISOString();
              },
            },
          })
        );
        break;
      case OutputFormat.html:
        return output(
          renderFile(join(process.cwd(), "assets", "pug", "graph.pug"), {
            title: `Report for ${this.options.initialTarget}`,
            baseChartData: JSON.stringify(
              this.items.map((item) => ({
                ...item,
                date: item.lastIssuanceDate
                  ? item.lastIssuanceDate.toISOString()
                  : null,
                linkedDomains: [...item.linkedDomains.values()],
              }))
            ),
            chartModes: {
              domains: [{ name: "Links between domains", value: "links" }],
              ips: [],
              wordcloud: [
                { name: "Links between words", value: "links" },
                { name: "Show domains", value: "domains" },
                {
                  name: "Words only",
                  value: "only-words",
                  changeChartOptions: true,
                  chartOption: "onlyWords",
                },
              ],
            },
            globalOptions: [{ name: "Only resolved", value: "only-resolved" }],
            command: process.argv.splice(2).join(" "),
          })
        );
      default:
        break;
    }
  }
}

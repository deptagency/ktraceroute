import kotlinx.cli.*

const val DEFAULT_PORT = 80
const val DEFAULT_MAX_HOPS = 64
const val DEFAULT_FIRST_HOP = 1
const val DEFAULT_TIMEOUT_MS = 500
const val DEFAULT_RETRIES = 3
const val DEFAULT_PACKET_SIZE = 52

fun main(args: Array<String>) {
    val parser = ArgParser("ktraceroute")
    val host by parser.option(ArgType.String, shortName = "n", description = "Host").required()
    val port by parser.option(ArgType.Int, shortName = "p", description = "Port").default(DEFAULT_PORT)
    val packetSize by parser.option(ArgType.Int, shortName = "ps", description = "Packet size")
        .default(DEFAULT_PACKET_SIZE)
    val maxHops by parser.option(ArgType.Int, shortName = "mh", description = "Max hops").default(DEFAULT_MAX_HOPS)
    val timeout by parser.option(ArgType.Int, shortName = "t", description = "Timeout (ms)")
        .default(DEFAULT_TIMEOUT_MS)
    val firstHop by parser.option(ArgType.Int, shortName = "fh", description = "First hop").default(DEFAULT_FIRST_HOP)
    val retries by parser.option(ArgType.Int, shortName = "r", description = "Retries").default(DEFAULT_RETRIES)

    parser.parse(args)
    val trArgs = Args(
        host,
        port,
        packetSize,
        maxHops,
        timeout,
        firstHop,
        retries
    )
    traceroute(trArgs)
}
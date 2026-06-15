using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Shared.ShellOperations
{
    /// <summary>
    /// Represents a server/node where DDoS protection rules are managed.
    /// </summary>
    public class HostServer
    {
        /// <summary>
        /// Gets or sets the unique identifier for the server.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Gets or sets the IP address of the server.
        /// </summary>
        public string IpAddress { get; set; }

        /// <summary>
        /// Gets or sets the SSH user to connect as.
        /// </summary>
        public string User { get; set; }
    }

    /// <summary>
    /// Represents a server configuration detailing port allocations.
    /// </summary>
    public class ServerConfiguration
    {
        /// <summary>
        /// Gets or sets the SFTP port for file transfers.
        /// </summary>
        public int SftpPort { get; set; }

        /// <summary>
        /// Gets or sets the main game server port.
        /// </summary>
        public int GamePort { get; set; }

        /// <summary>
        /// Gets or sets the query/telemetry port for the game server (0 if disabled).
        /// </summary>
        public int QueryPort { get; set; }

        /// <summary>
        /// Gets or sets the custom assigned ports mapping (e.g., Key="rcon", Value="27015/tcp").
        /// </summary>
        public Dictionary<string, string> OtherPorts { get; set; }
    }

    /// <summary>
    /// Represents an active service order containing port allocations.
    /// </summary>
    public class Order
    {
        /// <summary>
        /// Gets or sets the server configuration mapping ports.
        /// </summary>
        public ServerConfiguration ServerConfiguration { get; set; }
    }

    /// <summary>
    /// Simple result wrapper for SSH command execution.
    /// </summary>
    public class SshResult
    {
        /// <summary>
        /// Gets or sets the execution exit status code (0 for success).
        /// </summary>
        public int ExitStatus { get; set; }

        /// <summary>
        /// Gets or sets the error output from stderr if any.
        /// </summary>
        public string Error { get; set; }

        /// <summary>
        /// Gets or sets the standard output from stdout.
        /// </summary>
        public string Output { get; set; }
    }

    /// <summary>
    /// Abstraction for SSH transport execution on remote nodes.
    /// </summary>
    public interface ISshService
    {
        /// <summary>
        /// Executes a shell command on the specified node via SSH.
        /// </summary>
        /// <param name="ip">The IP address of the target server.</param>
        /// <param name="user">The SSH username.</param>
        /// <param name="command">The command string to execute.</param>
        /// <param name="ct">The cancellation token.</param>
        /// <returns>A task resolving to the SSH command execution result.</returns>
        Task<SshResult> RunCommandAsync(string ip, string user, string command, CancellationToken ct);
    }

    /// <summary>
    /// Abstraction to query orchestrator orders and servers from the database.
    /// </summary>
    public interface IOrchestratorDbContext
    {
        /// <summary>
        /// Retrieves the list of ready host servers.
        /// </summary>
        /// <param name="ct">The cancellation token.</param>
        /// <returns>A task resolving to the list of ready servers.</returns>
        Task<List<HostServer>> GetReadyServersAsync(CancellationToken ct);

        /// <summary>
        /// Retrieves active orders with their configurations for a given server.
        /// </summary>
        /// <param name="serverId">The unique ID of the server.</param>
        /// <param name="ct">The cancellation token.</param>
        /// <returns>A task resolving to the list of active orders on the server.</returns>
        Task<List<Order>> GetActiveOrdersForServerAsync(int serverId, CancellationToken ct);
    }

    /// <summary>
    /// Performs periodic "Passive Layer" cleanup of orphaned firewall artifacts on Linux nodes.
    /// This service ensures that even if active cleanup fails, the node state is eventually reconciled.
    /// Uses a bounded producer-consumer channel queue to process server node syncs in parallel.
    /// </summary>
    public class FirewallGarbageCollectionService : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly Channel<HostServer> _channel;
        private readonly ILogger<FirewallGarbageCollectionService> _logger;
        private const int MaxConcurrentWorkers = 3;

        /// <summary>
        /// Initializes a new instance of the <see cref="FirewallGarbageCollectionService"/> class.
        /// </summary>
        /// <param name="scopeFactory">The service scope factory to resolve scoped dependencies.</param>
        /// <param name="logger">The logger instance.</param>
        public FirewallGarbageCollectionService(
            IServiceScopeFactory scopeFactory,
            ILogger<FirewallGarbageCollectionService> logger)
        {
            _scopeFactory = scopeFactory;
            _logger = logger;
            _channel = Channel.CreateBounded<HostServer>(new BoundedChannelOptions(100)
            {
                FullMode = BoundedChannelFullMode.Wait
            });
        }

        /// <summary>
        /// Executes the background service, initiating the worker loops and periodic polling.
        /// </summary>
        /// <param name="stoppingToken">Triggered when the host is shutting down.</param>
        /// <returns>A task representing the background operation.</returns>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Starting Firewall Garbage Collection background service...");

            var workers = new Task[MaxConcurrentWorkers];
            for (int i = 0; i < MaxConcurrentWorkers; i++)
            {
                int workerId = i;
                workers[i] = Task.Run(() => WorkerLoop(workerId, stoppingToken), stoppingToken);
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await PollNodes(stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred during active server polling.");
                }

                // Run firewall GC sync every 6 hours
                await Task.Delay(TimeSpan.FromHours(6), stoppingToken);
            }

            _channel.Writer.Complete();
            await Task.WhenAll(workers);

            _logger.LogInformation("Firewall Garbage Collection background service stopped.");
        }

        /// <summary>
        /// Queries active servers and queues them for syncing.
        /// </summary>
        /// <param name="ct">The cancellation token.</param>
        /// <returns>A task representing the polling operation.</returns>
        private async Task PollNodes(CancellationToken ct)
        {
            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IOrchestratorDbContext>();

            var hostServers = await dbContext.GetReadyServersAsync(ct);
            _logger.LogInformation("Polled {Count} ready servers for firewall GC check.", hostServers.Count);

            foreach (var host in hostServers)
            {
                await _channel.Writer.WriteAsync(host, ct);
            }
        }

        /// <summary>
        /// Worker consumer loop that reads servers from the queue and syncs their firewall rules.
        /// </summary>
        /// <param name="workerId">The ID of the concurrent worker thread.</param>
        /// <param name="ct">The cancellation token.</param>
        /// <returns>A task representing the worker loop.</returns>
        private async Task WorkerLoop(int workerId, CancellationToken ct)
        {
            _logger.LogInformation("Firewall GC worker {WorkerId} started.", workerId);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var host = await _channel.Reader.ReadAsync(ct);
                    await SyncNodeFirewall(host, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in Firewall GC worker {WorkerId} processing queue.", workerId);
                }
            }

            _logger.LogInformation("Firewall GC worker {WorkerId} shut down.", workerId);
        }

        /// <summary>
        /// Compiles authorized ports on a server, generates the garbage collection script, and runs it on the node.
        /// </summary>
        /// <param name="host">The server node to sync.</param>
        /// <param name="ct">The cancellation token.</param>
        /// <returns>A task representing the sync operation.</returns>
        private async Task SyncNodeFirewall(HostServer host, CancellationToken ct)
        {
            _logger.LogInformation("Starting firewall garbage collection for server {ServerId} ({Ip}).", host.Id, host.IpAddress);

            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IOrchestratorDbContext>();
            var sshService = scope.ServiceProvider.GetRequiredService<ISshService>();

            // 1. Identify "Authorized" Pairs based on current source of truth
            var activeOrders = await dbContext.GetActiveOrdersForServerAsync(host.Id, ct);
            var authorizedPairs = new HashSet<string>();

            foreach (var order in activeOrders)
            {
                var config = order.ServerConfiguration;
                if (config == null) continue;

                // Standard Ports
                authorizedPairs.Add($"tcp:{config.SftpPort}");
                authorizedPairs.Add($"tcp:{config.GamePort}");
                authorizedPairs.Add($"udp:{config.GamePort}");

                if (config.QueryPort > 0)
                {
                    authorizedPairs.Add($"tcp:{config.QueryPort}");
                    authorizedPairs.Add($"udp:{config.QueryPort}");
                }

                // Other/Custom Ports (Format: "AssignedPort/Protocol")
                if (config.OtherPorts != null)
                {
                    foreach (var val in config.OtherPorts.Values)
                    {
                        if (string.IsNullOrWhiteSpace(val)) continue;

                        var parts = val.Split('/');
                        if (parts.Length == 2)
                        {
                            var assignedPort = parts[0];
                            var protocol = parts[1].ToLower();
                            authorizedPairs.Add($"{protocol}:{assignedPort}");
                        }
                    }
                }
            }

            if (authorizedPairs.Count == 0)
            {
                _logger.LogWarning("No authorized ports found for server {ServerId}. Skipping GC to prevent accidental flushing of all rules.", host.Id);
                return;
            }

            // 2. Format command using our sanitized shell operations class
            string command = GithubGameNodeShelloperations.GarbageCollectNft(string.Join(" ", authorizedPairs));

            // 3. Execute script on remote node via SSH
            var result = await sshService.RunCommandAsync(host.IpAddress, host.User, command, ct);

            // 4. Handle results and log status
            if (result.ExitStatus != 0)
            {
                _logger.LogError("Firewall GC failed on server {ServerId} ({Ip}) with exit status {ExitStatus}. Error: {Error}", 
                    host.Id, host.IpAddress, result.ExitStatus, result.Error);
            }
            else
            {
                _logger.LogInformation("Firewall GC completed successfully on server {ServerId} ({Ip}).", 
                    host.Id, host.IpAddress);
            }
        }
    }
}

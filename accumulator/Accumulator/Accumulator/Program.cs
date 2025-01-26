using System.Collections.Concurrent;
using System.Diagnostics;
using Accumulator.gRPC;
using Accumulator.Wallet;
using FASTER.core;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using static WalletService;

namespace Accumulator;

public class Transaction
{
    public byte[] Data;
    public long From;
    public long SeqNum;
    public long To;
    public long Value;
}

public class Program
{
    public static int NumTx = 1_000;
    public static int NumWallets = 10_000_000;

    static readonly Dictionary<int, string> NodeIpMapping = new Dictionary<int, string>
    {
        // { 0, "127.0.0.1" },
        // { 1, "127.0.0.1" },
        
        { 0, "192.168.1.10" },
        { 1, "192.168.1.11" },
        { 2, "192.168.1.12" },
        { 3, "192.168.1.13" },
        { 4, "192.168.1.14" },
        { 5, "192.168.1.15" },
        { 6, "192.168.1.16" },
        { 7, "192.168.1.17" },
        { 8, "192.168.1.18" },
        { 9, "192.168.1.19" },
        { 10, "192.168.1.20" },
        { 11, "192.168.1.21" },
        { 12, "192.168.1.22" },
        { 13, "192.168.1.23" },
        { 14, "192.168.1.24" },
        { 15, "192.168.1.25" },
        { 16, "192.168.1.26" },
        { 17, "192.168.1.27" },
        { 18, "192.168.1.28" },
        { 19, "192.168.1.29" },
        // { 20, "192.168.1.30" },
        // { 21, "192.168.1.31" },
        // { 22, "192.168.1.32" },
        // { 23, "192.168.1.33" },
        // { 24, "192.168.1.34" },
        // { 25, "192.168.1.35" },
        // { 26, "192.168.1.36" },
        // { 27, "192.168.1.37" },
        // { 28, "192.168.1.38" },
        // { 29, "192.168.1.39" }
    };

    static async Task Main(string[] args)
    {
        // Parse node ID and total partitions from command line arguments
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: dotnet run -- <nodeId> <totalPartitions>");
            return;
        }

        int nodeId = int.Parse(args[0]);
        int totalPartitions = int.Parse(args[1]);

        // Get IP address for the current node
        if (!NodeIpMapping.TryGetValue(nodeId, out var ipAddress))
        {
            Console.WriteLine($"No IP address found for node {nodeId}.");
            return;
        }

        // Configuration for FASTER store
        //var log = Devices.CreateLogDevice($"Logs/hlog-{nodeId}.log", preallocateFile: false);
        //var objLog = Devices.CreateLogDevice($"Logs/hlog-{nodeId}.obj.log", preallocateFile: false);
        var store = new FasterKV<long, Wallet.Wallet>(
            size: 1L << 30,
            logSettings: new LogSettings
            {
                LogDevice = new NullDevice(),
                ObjectLogDevice = new NullDevice(),
                MutableFraction = 1,
                PageSizeBits = 14,
                MemorySizeBits = 25
            });

        // Initialize wallets for this node's partition
        InitializeWallets(store, nodeId, totalPartitions);

        // Start gRPC server
        Console.WriteLine($"Node {nodeId}: Starting gRPC server...");
        var grpcServer = StartGrpcServer(store, ipAddress).RunAsync();
        
        // Wait for all nodes to be ready
        await WaitForAllNodesReady(nodeId, totalPartitions);

        // Start transaction processing in the background
        _ = Task.Run(async () =>
        {
            var transactions = GenerateTransactions(NumTx, NumWallets);
            await ProcessTransactionsAsync(store, transactions, nodeId, totalPartitions);
        });

        // Start periodic checkpointing
        _ = Task.Run(async () =>
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromMinutes(5)); // Checkpoint every 5 minutes
                Console.WriteLine($"Node {nodeId}: Taking checkpoint...");
                var stopwatch = Stopwatch.StartNew();
                store.TakeFullCheckpointAsync(CheckpointType.FoldOver).GetAwaiter().GetResult();
                stopwatch.Stop();
                Console.WriteLine($"Node {nodeId}: Checkpoint completed in {stopwatch.ElapsedMilliseconds} ms.");
            }
        });

        // Keep the gRPC server running indefinitely
        await grpcServer;
    }

    static void InitializeWallets(FasterKV<long, Wallet.Wallet> store, int nodeId, int totalPartitions)
    {
        Console.WriteLine($"Initializing wallets for node {nodeId}...");
        var initTasks = Enumerable.Range(0, Environment.ProcessorCount).Select(thread =>
        {
            return Task.Run(() =>
            {
                using var session = store.NewSession(new WalletFunctions());
                for (long i = thread; i < NumWallets; i += Environment.ProcessorCount)
                {
                    if (GetPartition(i, totalPartitions) == nodeId)
                    {
                        session.Upsert(i, new Wallet.Wallet { Balance = 1000, SeqNum = 0 });
                    }
                }
            });
        });
        Task.WaitAll(initTasks.ToArray());
        Console.WriteLine($"Node {nodeId}: Wallet initialization complete.");
    }

    static Transaction[] GenerateTransactions(int totalTransactions, int totalWallets)
    {
        Console.WriteLine("Generating transactions...");
        var random = new Random();
        var transactions = new Transaction[totalTransactions];
        Parallel.For(0, totalTransactions, i =>
        {
            transactions[i] = new Transaction
            {
                From = random.Next(0, totalWallets),
                To = random.Next(0, totalWallets),
                Value = random.Next(1, 500),
                Data = new byte[256],
                SeqNum = 1
            };
        });
        return transactions;
    }

    static async Task ProcessTransactionsAsync(FasterKV<long, Wallet.Wallet> store, Transaction[] transactions,
        int nodeId, int totalPartitions)
    {
        Console.WriteLine($"Node {nodeId}: Processing {transactions.Length} transactions with {1} threads...");
        var stopwatch = Stopwatch.StartNew();

        var transactionBatches = transactions.Chunk(1);

        // Shared node updates dictionary for merging at the end
        var sharedNodeUpdates = new ConcurrentDictionary<int, List<WalletUpdate>>();

        var local_processing_start = Stopwatch.StartNew();
        await Parallel.ForEachAsync(transactionBatches, async (batch, _) =>
        {
            using var session = store.NewSession(new WalletFunctions());
            var localNodeUpdates = new Dictionary<int, List<WalletUpdate>>();

            foreach (var tx in batch)
            {
                int senderPartition = GetPartition(tx.From, totalPartitions);
                int receiverPartition = GetPartition(tx.To, totalPartitions);

                if (senderPartition == nodeId)
                {
                    if (session.Read(tx.From, out var senderWallet).Found && senderWallet.Balance >= tx.Value &&
                        senderWallet.SeqNum < tx.SeqNum)
                    {
                        senderWallet.Balance -= tx.Value;
                        senderWallet.SeqNum = tx.SeqNum;
                        session.Upsert(tx.From, senderWallet);

                        if (receiverPartition == nodeId)
                        {
                            // Update receiver locally
                            if (session.Read(tx.To, out var receiverWallet).Found)
                            {
                                receiverWallet.Balance += tx.Value;
                                session.Upsert(tx.To, receiverWallet);
                            }
                        }
                        else
                        {
                            // Add the update to the thread-local batch for the target node
                            if (!localNodeUpdates.TryGetValue(receiverPartition, out var updatesList))
                            {
                                updatesList = new List<WalletUpdate>();
                                localNodeUpdates[receiverPartition] = updatesList;
                            }

                            updatesList.Add(new WalletUpdate
                            {
                                WalletId = tx.To,
                                Amount = tx.Value,
                                SeqNum = tx.SeqNum
                            });
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Node {nodeId}: Invalid transaction from {tx.From} to {tx.To}.");
                        var found = session.Read(tx.From, out var _);
                        Console.WriteLine($"Found in the store? {found.Found}");
                        if (found.Found)
                        {
                            Console.WriteLine($"Balance: {senderWallet.Balance}, tx value: {tx.Value}, seq num: {senderWallet.SeqNum}, tx seq num: {tx.SeqNum}");
                        }
                    }
                }
            }

            // Merge localNodeUpdates into sharedNodeUpdates
            foreach (var kvp in localNodeUpdates)
            {
                sharedNodeUpdates.AddOrUpdate(
                    kvp.Key,
                    _ => kvp.Value, // If key does not exist, add it
                    (_, existingList) =>
                    {
                        lock (existingList)
                        {
                            existingList.AddRange(kvp.Value); // Merge lists
                        }

                        return existingList;
                    });
            }
        });
        local_processing_start.Stop();
        Console.WriteLine($"Node {nodeId}: Local processing took {local_processing_start.ElapsedMilliseconds} ms.");

        // Send batched updates to each partition
        var sending_updates_start = Stopwatch.StartNew();
        var batchTasks = sharedNodeUpdates.Select(kvp => SendBatchUpdateToNode(kvp.Key, kvp.Value));
        await Task.WhenAll(batchTasks);
        sending_updates_start.Stop();
        Console.WriteLine($"Node {nodeId}: Sending updates took {sending_updates_start.ElapsedMilliseconds} ms.");

        stopwatch.Stop();
        Console.WriteLine($"Node {nodeId}: Transaction processing took {stopwatch.ElapsedMilliseconds} ms.");
    }
    
    static int GetPartition(long walletId, int totalPartitions)
    {
        return (int)(walletId % totalPartitions);
    }

    // static async Task SendUpdateToNode(string targetIp, int partition, long walletId, long amount, long seqNum)
    // {
    //     try
    //     {
    //         var channel = GrpcChannel.ForAddress($"http://{targetIp}:{5000 + partition}", new GrpcChannelOptions
    //         {
    //             HttpHandler = new SocketsHttpHandler
    //             {
    //                 EnableMultipleHttp2Connections = true
    //             }
    //         });
    //         var client = new WalletServiceClient(channel);
    //
    //         var response = await client.UpdateWalletAsync(new WalletUpdateRequest
    //         {
    //             WalletId = walletId,
    //             Amount = amount,
    //             SeqNum = seqNum
    //         });
    //
    //         if (!response.Success)
    //         {
    //             Console.WriteLine($"Failed to update wallet {walletId} on node {partition} at {targetIp}.");
    //         }
    //     }
    //     catch (Exception ex)
    //     {
    //         Console.WriteLine($"Error updating wallet {walletId} on node {partition} at {targetIp}: {ex.Message}");
    //     }
    // }

    static async Task SendBatchUpdateToNode(int partition, List<WalletUpdate> updates)
    {
        Console.WriteLine($"Sending {updates.Count} updates to partition {partition}...");
        if (!NodeIpMapping.TryGetValue(partition, out var targetIp))
        {
            Console.WriteLine($"No IP address found for node {partition}.");
            return;
        }

        try
        {
            var channel = GrpcChannel.ForAddress($"http://{targetIp}:{5000}", new GrpcChannelOptions
            {
                HttpHandler = new SocketsHttpHandler
                {
                    EnableMultipleHttp2Connections = true
                }
            });

            var client = new WalletServiceClient(channel);

            var response = await client.UpdateWalletsAsync(new WalletBatchUpdateRequest
            {
                Updates = { updates }
            });

            if (!response.Success)
            {
                Console.WriteLine($"Batch update failed for node {partition} at {targetIp}.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending batch update to node {partition} at {targetIp}: {ex.Message}");
        }
    }

    static async Task WaitForAllNodesReady(int nodeId, int totalPartitions)
    {
        Console.WriteLine($"Node {nodeId}: Waiting for all nodes to be ready...");
        await Task.Delay(5000);
    
        var unresponsiveNodes = Enumerable.Range(0, totalPartitions)
            .Where(id => id != nodeId)
            .ToList();

        const int maxRetries = 15; // Maximum retries
        const int baseDelayMs = 100; // Base delay for exponential backoff
        int retryCount = 0;

        while (unresponsiveNodes.Count > 0)
        {
            if (retryCount >= maxRetries)
            {
                Console.WriteLine($"Node {nodeId}: Timed out waiting for nodes {string.Join(", ", unresponsiveNodes)} to be ready.");
                return;
            }
            retryCount++;
            Console.WriteLine($"Node {nodeId}: Attempt {retryCount}, contacting {unresponsiveNodes.Count} unresponsive nodes...");

            // Check readiness for remaining unresponsive nodes
            var tasks = unresponsiveNodes.Select(async otherNodeId =>
            {
                if (!NodeIpMapping.TryGetValue(otherNodeId, out var targetIp))
                {
                    Console.WriteLine($"Node {nodeId}: No IP address found for node {otherNodeId}.");
                    return false;
                }

                return await IsNodeReady(targetIp, otherNodeId);
            });

            var results = await Task.WhenAll(tasks);

            // Remove responsive nodes from the unresponsive list
            unresponsiveNodes = unresponsiveNodes
                .Where((nodeId, index) => !results[index])
                .ToList();

            if (unresponsiveNodes.Count > 0)
            {
                Console.WriteLine($"Node {nodeId}: {unresponsiveNodes.Count} nodes still unresponsive. Retrying...");

                // Wait before retrying (exponential backoff with a cap)
                await Task.Delay(Math.Min(baseDelayMs * (1 << retryCount), 5000)); // Cap at 5 seconds
            }
        }

        Console.WriteLine($"Node {nodeId}: All nodes are ready.");
    }
    
    static async Task<bool> IsNodeReady(string targetIp, int nodeId)
    {
        try
        {
            var channel = GrpcChannel.ForAddress($"http://{targetIp}:{5000}");
            var client = new WalletServiceClient(channel);

            var response = await client.ReadyAsync(new ReadyRequest());
            return response.Ready;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking readiness of node {nodeId} at {targetIp}: {ex.Message}");
            return false;
        }
    }

    static IHost StartGrpcServer(FasterKV<long, Wallet.Wallet> store, string ipAddress)
    {
        return Host.CreateDefaultBuilder()
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.ConfigureServices(services =>
                {
                    services.AddGrpc();
                    services.AddSingleton(store);
                    services.AddSingleton<WalletServiceImpl>();
                });

                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => { endpoints.MapGrpcService<WalletServiceImpl>(); });
                });

                // Configure Kestrel to listen on the node's IP address and use HTTP/2
                webBuilder.ConfigureKestrel(options =>
                {
                    options.Listen(System.Net.IPAddress.Parse(ipAddress), 5000,
                        listenOptions =>
                        {
                            listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2;
                        });
                });
            })
            .Build();
    }
}
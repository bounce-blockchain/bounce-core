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
    public static int NumTx = 10_000;
    public static int NumWallets = 1_000;
    
    static readonly Dictionary<int, string> NodeIpMapping = new Dictionary<int, string>
    {
        { 0, "192.168.1.10" },
        { 1, "192.168.1.11" }
        // { 2, "192.168.1.12" },
        // { 3, "192.168.1.13" }
        // { 0, "127.0.0.1" },
        // { 1, "127.0.0.1" },
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
        var log = Devices.CreateLogDevice($"Logs/hlog-{nodeId}.log", preallocateFile: false);
        var objLog = Devices.CreateLogDevice($"Logs/hlog-{nodeId}.obj.log", preallocateFile: false);
        var store = new FasterKV<long, Wallet.Wallet>(
            size: 1L << 25,
            logSettings: new LogSettings
            {
                LogDevice = log,
                ObjectLogDevice = objLog,
                MutableFraction = 0.1,
                PageSizeBits = 14,
                MemorySizeBits = 25
            });

        // Initialize wallets for this node's partition
        InitializeWallets(store, nodeId, totalPartitions);

        // Start gRPC server
        var grpcServer = StartGrpcServer(store, ipAddress, nodeId);
        

        // Start transaction processing in the background
        _ = Task.Run(() =>
        {
            var transactions = GenerateTransactions(NumTx, NumWallets);
            Task.Delay(TimeSpan.FromSeconds(3)); // Wait for other servers to be ready start
            ProcessTransactionsAsync(store, transactions, nodeId, totalPartitions);
        });

        // Start periodic checkpointing
        _ = Task.Run(async () =>
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromMinutes(5)); // Checkpoint every 5 minutes
                Console.WriteLine($"Node {nodeId}: Taking checkpoint...");
                store.TakeFullCheckpointAsync(CheckpointType.FoldOver).GetAwaiter().GetResult();
                Console.WriteLine($"Node {nodeId}: Checkpoint completed.");
            }
        });

        // Keep the gRPC server running indefinitely
        await grpcServer.RunAsync();
    }

    static void InitializeWallets(FasterKV<long, Wallet.Wallet> store, int nodeId, int totalPartitions)
    {
        Console.WriteLine($"Initializing wallets for node {nodeId}...");
        long totalWallets = NumWallets; // Total wallets across all partitions
        var initTasks = Enumerable.Range(0, Environment.ProcessorCount).Select(thread =>
        {
            return Task.Run(() =>
            {
                using var session = store.NewSession(new WalletFunctions());
                for (long i = thread; i < totalWallets; i += Environment.ProcessorCount)
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
                Value = random.Next(1, 1000),
                Data = new byte[256],
                SeqNum = 1
            };
        });
        return transactions;
    }

    static async Task ProcessTransactionsAsync(FasterKV<long, Wallet.Wallet> store, Transaction[] transactions, int nodeId, int totalPartitions)
    {
        Console.WriteLine($"Node {nodeId}: Processing transactions...");
        var stopwatch = Stopwatch.StartNew();

        var transactionBatches = transactions.Chunk(Environment.ProcessorCount);

        // Use Parallel.ForEachAsync for async transaction processing
        await Parallel.ForEachAsync(transactionBatches, async (batch, _) =>
        {
            using var session = store.NewSession(new WalletFunctions());
            foreach (var tx in batch)
            {
                int senderPartition = GetPartition(tx.From, totalPartitions);
                int receiverPartition = GetPartition(tx.To, totalPartitions);

                if (senderPartition == nodeId)
                {
                    if (session.Read(tx.From, out var senderWallet).Found && senderWallet.Balance >= tx.Value && senderWallet.SeqNum < tx.SeqNum)
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
                        else if (NodeIpMapping.TryGetValue(receiverPartition, out var targetIp))
                        {
                            // Fire-and-forget the remote update
                            await SendUpdateToNode(targetIp, receiverPartition, tx.To, tx.Value, tx.SeqNum);
                        }
                        else
                        {
                            Console.WriteLine($"No IP address found for node {receiverPartition}.");
                        }
                    }
                }
            }
        });

        stopwatch.Stop();
        Console.WriteLine($"Node {nodeId}: Transaction processing took {stopwatch.ElapsedMilliseconds} ms.");
    }

    static int GetPartition(long walletId, int totalPartitions)
    {
        return (int)(walletId % totalPartitions);
    }

    static async Task SendUpdateToNode(string targetIp, int partition, long walletId, long amount, long seqNum)
    {
        try
        {
            var channel = GrpcChannel.ForAddress($"http://{targetIp}:{5000 + partition}", new GrpcChannelOptions
            {
                HttpHandler = new SocketsHttpHandler
                {
                    EnableMultipleHttp2Connections = true
                }
            });
            var client = new WalletServiceClient(channel);

            var response = await client.UpdateWalletAsync(new WalletUpdateRequest
            {
                WalletId = walletId,
                Amount = amount,
                SeqNum = seqNum
            });

            if (!response.Success)
            {
                Console.WriteLine($"Failed to update wallet {walletId} on node {partition} at {targetIp}.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error updating wallet {walletId} on node {partition} at {targetIp}: {ex.Message}");
        }
    }


    static IHost StartGrpcServer(FasterKV<long, Wallet.Wallet> store, string ipAddress, int nodeId)
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
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGrpcService<WalletServiceImpl>();
                    });
                });

                // Configure Kestrel to listen on the node's IP address and use HTTP/2
                webBuilder.ConfigureKestrel(options =>
                {
                    options.Listen(System.Net.IPAddress.Parse(ipAddress), 5000 + nodeId, listenOptions =>
                    {
                        listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2;
                    });
                });
            })
            .Build();
    }


}
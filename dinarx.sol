// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";

import "./interfaces/IStakingBooster.sol";
import "./interfaces/IVotingDAO.sol";
import "./interfaces/ILiquidityRewardPool.sol";
import "./vesting/VestingManager.sol";
import "./multisig/MultiSigController.sol";

/**
 * @title DinarX
 * @author Your Company/Team
 * @notice Token ERC20 dengan fitur vesting, kontrol akses, dan upgradeability.
 * @dev Menggunakan OpenZeppelin Upgradeable Contracts dan EIP-712 untuk signature off-chain.
 */
contract DinarX is
    Initializable,
    ERC20Upgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20Upgradeable for IERC20Upgradeable;
    using SafeMathUpgradeable for uint256;
    using ECDSAUpgradeable for bytes32;

    // Constants
    uint256 public constant FIXED_SUPPLY = 100_000_000_000 * 1e18;
    uint256 public constant MAX_CLAIM_PER_ADDRESS = 5_000_000 * 1e18;
    uint256 public constant MAX_VESTINGS_PER_USER = 100;
    uint256 public maxClaimsPerTx;

    bytes32 private constant CLAIM_FROM_DRMX_BURN_TYPEHASH = keccak256(
        "ClaimFromDRMXBurn(address user,uint256 drmxAmount,uint256 duration,uint256 cliff,uint256 expiry,bytes32 proof,uint256 nonce)"
    );

    // EIP-712 Domain Separator
    bytes32 private _domainSeparator;

    // Interfaces
    IVotingDAO public daoGovernance;
    IStakingBooster public stakingBooster;
    ILiquidityRewardPool public liquidityRewardPool;

    // Address Configuration
    address public whitelistSigner;
    address public daoReceiver;
    address public stakingRewardPool;
    address public grantReceiver;

    // State Variables
    uint256 public baseConversionRate;
    uint256 public vestingPoolRemaining;
    uint256 public totalVestedAllocated;
    uint256 public expiredTotal;
    uint256 public globalTotalClaimed;
    uint256 public cooldownPeriod;
    uint256 public maxGasUsage;

    bool public vestingPaused;
    bool public claimPaused;

    // Mappings
    mapping(bytes32 => bool) public processedSinkProofs;
    mapping(address => uint256) public userTotalClaimed;
    mapping(address => bool) public blacklisted;
    mapping(bytes32 => bool) public executedOperations;
    mapping(string => Timelock) public pendingChanges;
    mapping(address => uint256) public lastClaimTime;
    uint256 public governanceNonce;

    // Events
    event SinkClaimScheduled(address indexed user, uint256 amount, uint256 start, uint256 duration, uint256 cliff, uint256 expiry, uint256 booster, bytes32 proof);
    event DNRXClaimed(address indexed user, uint256 amount);
    event DNRXExpired(address indexed user, uint256 amount);
    event RewardsFunded(uint256 dnrx, uint256 drmx);
    event ExpiredTokensRecovered(address indexed to, uint256 amount, string route);
    event ConversionRateUpdated(uint256 newRate);
    event PauseStateUpdated(bool vestingPaused, bool claimPaused);
    event RedistributionAddressesUpdated(address dao, address staking, address grant);
    event WhitelistSignerUpdated(address newSigner);
    event ForeignTokenRecovered(address token, address to, uint256 amount);
    event ETHRecovered(address to, uint256 amount);
    event DRMXBurned(address indexed user, uint256 drmxAmount, uint256 conversionRate);
    event BatchExpiredRecovered(uint256 totalAmount, string route);
    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);
    event MultiSigOperationExecuted(bytes32 operationHash);
    event TimelockProposed(string parameter, uint256 value, uint256 executeTimestamp);
    event TimelockExecuted(string parameter, uint256 value);
    event TokensReceived(address sender, uint256 amount);
    event StakingBoosterUpdated(address newBooster);
    event DAOGovernanceUpdated(address newDAO);
    event CooldownPeriodUpdated(uint256 newPeriod);
    event MaxGasUsageUpdated(uint256 newMaxGas);
    event DomainSeparatorUpdated(bytes32 newSeparator);

    struct Timelock {
        uint256 value;
        uint256 timestamp;
    }

    // Komponen Modular
    MultiSigController public multiSig;
    VestingManager public vestingManager;

    /**
     * @notice Inisialisasi kontrak setelah deployment
     * @param _dao Alamat DAO governance
     * @param _booster Alamat staking booster
     * @param _rewardPool Alamat pool reward likuiditas
     * @param _signer Alamat signer whitelist
     * @param _multiSigOwners Array dari tiga alamat multisig owner
     * @param timelock Alamat TimelockController
     */
    function initialize(
        address _dao,
        address _booster,
        address _rewardPool,
        address _signer,
        address[3] memory _multiSigOwners,
        address timelock
    ) public initializer {
        __ERC20_init("DinarX", "DNRX");
        __Ownable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _mint(msg.sender, FIXED_SUPPLY);
        _transferOwnership(timelock);

        daoGovernance = IVotingDAO(_dao);
        stakingBooster = IStakingBooster(_booster);
        liquidityRewardPool = ILiquidityRewardPool(_rewardPool);
        whitelistSigner = _signer;

        baseConversionRate = 1000;
        cooldownPeriod = 1 days;
        maxGasUsage = 1_500_000;
        maxClaimsPerTx = 20;

        multiSig = new MultiSigController(_multiSigOwners);
        vestingManager = new VestingManager(address(this));

        _updateDomainSeparator();
    }

    /**
     * @notice Update domain separator setelah upgrade
     */
    function _updateDomainSeparator() private {
        _domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("DinarX")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
        emit DomainSeparatorUpdated(_domainSeparator);
    }

    /**
     * @notice Otorisasi upgrade kontrak
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        _updateDomainSeparator();
    }

    /**
     * @notice Set alamat signer baru
     */
    function setWhitelistSigner(address signer) external onlyOwner {
        require(signer != address(0), "Invalid signer address");
        whitelistSigner = signer;
        emit WhitelistSignerUpdated(signer);
    }

    /**
     * @notice Aktifkan/pause fitur klaim dan vesting
     */
    function setPauseState(bool _vesting, bool _claim) external onlyOwner {
        vestingPaused = _vesting;
        claimPaused = _claim;
        emit PauseStateUpdated(_vesting, _claim);
    }

    /**
     * @notice Perbarui rasio konversi DRMX ke DNRX
     */
    function updateConversionRate(uint256 newRate) external onlyOwner {
        require(newRate > 0, "Invalid rate");
        baseConversionRate = newRate;
        emit ConversionRateUpdated(newRate);
    }

    /**
     * @notice Saldo awal vesting dari pemilik
     */
    function fundVestingPool(uint256 amount) external onlyOwner {
        require(amount > 0, "Invalid amount");
        require(balanceOf(_msgSender()) >= amount, "Insufficient balance");
        _transfer(_msgSender(), address(vestingManager), amount);
        vestingManager.updateVestingPoolBalance(amount);
    }

    /**
     * @notice Klaim semua token yang tersedia sesuai jadwal
     */
    function claimVested() external nonReentrant whenClaimActive notBlacklisted gasLimit claimCooldown {
        uint256 totalClaimable = vestingManager.claimVested(msg.sender, maxClaimsPerTx);
        require(totalClaimable > 0, "Nothing to claim");

        userTotalClaimed[msg.sender] += totalClaimable;
        globalTotalClaimed += totalClaimable;
        lastClaimTime[msg.sender] = block.timestamp;

        _transfer(address(vestingManager), msg.sender, totalClaimable);
        emit DNRXClaimed(msg.sender, totalClaimable);
    }

    /**
     * @notice Klaim satu entri vesting berdasarkan indeks
     */
    function claimSingleVesting(uint256 index) external nonReentrant whenClaimActive notBlacklisted {
        uint256 claimable = vestingManager.claimSingleVesting(msg.sender, index);
        require(claimable > 0, "Nothing to claim");

        userTotalClaimed[msg.sender] += claimable;
        globalTotalClaimed += claimable;

        _transfer(address(vestingManager), msg.sender, claimable);
        emit DNRXClaimed(msg.sender, claimable);
    }

    /**
     * @notice Tandai semua vesting yang kadaluarsa
     */
    function markExpiredAll() external notBlacklisted {
        uint256 markedCount = vestingManager.markExpiredAll(msg.sender);
        require(markedCount > 0, "No expirable vestings");
    }

    /**
     * @notice Pulihkan token yang kadaluarsa ke DAO
     */
    function recoverExpiredToDAO(uint256 amount) external onlyOwner {
        vestingManager.recoverExpiredToDAO(amount);
        emit ExpiredTokensRecovered(daoReceiver, amount, "DAO");
    }

    /**
     * @notice Masukkan akun ke daftar hitam
     */
    function blacklist(address _account) external onlyOwner {
        blacklisted[_account] = true;
        emit Blacklisted(_account);
    }

    /**
     * @notice Hapus akun dari daftar hitam
     */
    function unblacklist(address _account) external onlyOwner {
        blacklisted[_account] = false;
        emit UnBlacklisted(_account);
    }

    /**
     * @notice Eksekusi operasi multisig
     */
    function executeOperation(
        bytes32 operationHash,
        bytes[] calldata signatures
    ) external onlyMultiSigOwner {
        multiSig.executeOperation(operationHash, signatures);
        emit MultiSigOperationExecuted(operationHash);
    }

    /**
     * @notice Usulkan perubahan rasio konversi via timelock
     */
    function proposeConversionRateChange(uint256 newRate) external onlyOwner {
        pendingChanges["conversionRate"] = Timelock({
            value: newRate,
            timestamp: block.timestamp + 3 days
        });
        emit TimelockProposed("conversionRate", newRate, block.timestamp + 3 days);
    }

    /**
     * @notice Terapkan perubahan timelocked
     */
    function applyChange(string memory param) external {
        Timelock storage change = pendingChanges[param];
        require(change.timestamp > 0, "No pending change");
        require(block.timestamp >= change.timestamp, "Timelock active");
        require(msg.sender == owner(), "Unauthorized");

        if (keccak256(abi.encodePacked(param)) == keccak256(abi.encodePacked("conversionRate"))) {
            baseConversionRate = change.value;
            emit ConversionRateUpdated(change.value);
        } else if (keccak256(abi.encodePacked(param)) == keccak256(abi.encodePacked("cooldownPeriod"))) {
            cooldownPeriod = change.value;
            emit CooldownPeriodUpdated(change.value);
        } else if (keccak256(abi.encodePacked(param)) == keccak256(abi.encodePacked("maxGasUsage"))) {
            require(change.value == 0 || change.value >= 300_000, "Gas too low");
            maxGasUsage = change.value;
            emit MaxGasUsageUpdated(change.value);
        } else if (keccak256(abi.encodePacked(param)) == keccak256(abi.encodePacked("maxClaimsPerTx"))) {
            require(change.value > 0 && change.value <= 100, "Invalid range");
            maxClaimsPerTx = change.value;
        } else {
            revert("Unsupported timelock parameter");
        }
        delete pendingChanges[param];
        emit TimelockExecuted(param, change.value);
    }

    /**
     * @notice Pulihkan token asing
     */
    function recoverForeignToken(address token, address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid address");
        require(token != address(this), "Cannot recover DNRX");
        IERC20Upgradeable(token).safeTransfer(to, amount);
        emit ForeignTokenRecovered(token, to, amount);
    }

    /**
     * @notice Pulihkan ETH yang dikirim ke kontrak
     */
    function recoverETH(address payable to) external onlyOwner {
        require(to != address(0), "Invalid address");
        uint256 balance = address(this).balance;
        require(balance > 0, "No ETH available");
        (bool sent,) = to.call{value: balance}("");
        require(sent, "Transfer failed");
        emit ETHRecovered(to, balance);
    }

    /**
     * @notice Fallback - tidak diperbolehkan
     */
    fallback() external {
        revert("Direct calls not allowed");
    }

    receive() external payable {
        emit TokensReceived(msg.sender, msg.value);
    }

    // Modifier dengan error messages deskriptif

    modifier whenVestingActive() {
        require(!vestingPaused, "Vesting paused");
        _;
    }

    modifier whenClaimActive() {
        require(!claimPaused, "Claim paused");
        _;
    }

    modifier notBlacklisted() {
        require(!blacklisted[msg.sender], "Address blacklisted");
        _;
    }

    modifier onlyMultiSigOwner() {
        require(multiSig.isOwner(msg.sender), "Not multisig owner");
        _;
    }

    modifier gasLimit() {
        if (maxGasUsage > 0) {
            uint256 startGas = gasleft();
            _;
            require(startGas - gasleft() <= maxGasUsage, "Gas limit exceeded");
        } else {
            _;
        }
    }

    modifier claimCooldown() {
        require(block.timestamp >= lastClaimTime[msg.sender] + cooldownPeriod, "Cooldown active");
        _;
    }

    // Storage Gap untuk upgrade masa depan
    uint256[50] private __gap;
}
/* eslint-disable */
// This file was generated by [rspc](https://github.com/oscartbeaumont/rspc). Do not edit this file manually.

export type Procedures = {
    queries: 
        { key: "backups.getAll", input: never, result: GetAll } | 
        { key: "buildInfo", input: never, result: BuildInfo } | 
        { key: "categories.list", input: InstanceArgs<null>, result: { [key in Category]: number } } | 
        { key: "files.get", input: InstanceArgs<GetArgs>, result: { id: number; pub_id: number[]; kind: number | null; key_id: number | null; hidden: boolean | null; favorite: boolean | null; important: boolean | null; note: string | null; date_created: string | null; date_accessed: string | null; file_paths: FilePath[] } | null } | 
        { key: "files.getEphemeralMediaData", input: string, result: MediaMetadata | null } | 
        { key: "files.getMediaData", input: InstanceArgs<number>, result: MediaMetadata } | 
        { key: "files.getPath", input: InstanceArgs<number>, result: string | null } | 
        { key: "invalidation.test-invalidate", input: never, result: number } | 
        { key: "jobs.isActive", input: InstanceArgs<null>, result: boolean } | 
        { key: "jobs.reports", input: never, result: { [key: string]: JobGroup[] } } | 
        { key: "library.list", input: never, result: LibraryConfigWrapped[] } | 
        { key: "library.statistics", input: InstanceArgs<null>, result: Statistics } | 
        { key: "locations.get", input: InstanceArgs<number>, result: Location | null } | 
        { key: "locations.getWithRules", input: InstanceArgs<number>, result: LocationWithIndexerRules | null } | 
        { key: "locations.indexer_rules.get", input: InstanceArgs<number>, result: IndexerRule } | 
        { key: "locations.indexer_rules.list", input: InstanceArgs<null>, result: IndexerRule[] } | 
        { key: "locations.indexer_rules.listForLocation", input: InstanceArgs<number>, result: IndexerRule[] } | 
        { key: "locations.list", input: InstanceArgs<null>, result: Location[] } | 
        { key: "nodeState", input: never, result: NodeState } | 
        { key: "nodes.listLocations", input: InstanceArgs<string | null>, result: ExplorerItem[] } | 
        { key: "notifications.dismiss", input: NotificationId, result: null } | 
        { key: "notifications.dismissAll", input: never, result: null } | 
        { key: "notifications.get", input: never, result: Notification[] } | 
        { key: "p2p.nlmState", input: never, result: { [key: string]: LibraryData } } | 
        { key: "preferences.get", input: InstanceArgs<null>, result: LibraryPreferences } | 
        { key: "search.ephemeralPaths", input: InstanceArgs<EphemeralPathSearchArgs>, result: NonIndexedFileSystemEntries } | 
        { key: "search.objects", input: InstanceArgs<ObjectSearchArgs>, result: SearchData<ExplorerItem> } | 
        { key: "search.objectsCount", input: InstanceArgs<{ filter?: ObjectFilterArgs }>, result: number } | 
        { key: "search.paths", input: InstanceArgs<FilePathSearchArgs>, result: SearchData<ExplorerItem> } | 
        { key: "search.pathsCount", input: InstanceArgs<{ filter?: FilePathFilterArgs }>, result: number } | 
        { key: "sync.messages", input: InstanceArgs<null>, result: CRDTOperation[] } | 
        { key: "tags.get", input: InstanceArgs<number>, result: Tag | null } | 
        { key: "tags.getForObject", input: InstanceArgs<number>, result: Tag[] } | 
        { key: "tags.getWithObjects", input: InstanceArgs<number[]>, result: { [key: number]: number[] } } | 
        { key: "tags.list", input: InstanceArgs<null>, result: Tag[] } | 
        { key: "volumes.list", input: never, result: Volume[] },
    mutations: 
        { key: "backups.backup", input: InstanceArgs<null>, result: string } | 
        { key: "backups.delete", input: string, result: null } | 
        { key: "backups.restore", input: string, result: null } | 
        { key: "files.copyFiles", input: InstanceArgs<FileCopierJobInit>, result: null } | 
        { key: "files.cutFiles", input: InstanceArgs<FileCutterJobInit>, result: null } | 
        { key: "files.deleteFiles", input: InstanceArgs<FileDeleterJobInit>, result: null } | 
        { key: "files.duplicateFiles", input: InstanceArgs<FileCopierJobInit>, result: null } | 
        { key: "files.eraseFiles", input: InstanceArgs<FileEraserJobInit>, result: null } | 
        { key: "files.removeAccessTime", input: InstanceArgs<number[]>, result: null } | 
        { key: "files.renameFile", input: InstanceArgs<RenameFileArgs>, result: null } | 
        { key: "files.setFavorite", input: InstanceArgs<SetFavoriteArgs>, result: null } | 
        { key: "files.setNote", input: InstanceArgs<SetNoteArgs>, result: null } | 
        { key: "files.updateAccessTime", input: InstanceArgs<number[]>, result: null } | 
        { key: "invalidation.test-invalidate-mutation", input: InstanceArgs<null>, result: null } | 
        { key: "jobs.cancel", input: InstanceArgs<string>, result: null } | 
        { key: "jobs.clear", input: InstanceArgs<string>, result: null } | 
        { key: "jobs.clearAll", input: InstanceArgs<null>, result: null } | 
        { key: "jobs.generateThumbsForLocation", input: InstanceArgs<GenerateThumbsForLocationArgs>, result: null } | 
        { key: "jobs.identifyUniqueFiles", input: InstanceArgs<IdentifyUniqueFilesArgs>, result: null } | 
        { key: "jobs.objectValidator", input: InstanceArgs<ObjectValidatorArgs>, result: null } | 
        { key: "jobs.pause", input: InstanceArgs<string>, result: null } | 
        { key: "jobs.resume", input: InstanceArgs<string>, result: null } | 
        { key: "library.create", input: CreateLibraryArgs, result: LibraryConfigWrapped } | 
        { key: "library.delete", input: string, result: null } | 
        { key: "library.edit", input: EditLibraryArgs, result: null } | 
        { key: "locations.addLibrary", input: InstanceArgs<LocationCreateArgs>, result: null } | 
        { key: "locations.create", input: InstanceArgs<LocationCreateArgs>, result: null } | 
        { key: "locations.delete", input: InstanceArgs<number>, result: null } | 
        { key: "locations.fullRescan", input: InstanceArgs<FullRescanArgs>, result: null } | 
        { key: "locations.indexer_rules.create", input: InstanceArgs<IndexerRuleCreateArgs>, result: null } | 
        { key: "locations.indexer_rules.delete", input: InstanceArgs<number>, result: null } | 
        { key: "locations.relink", input: InstanceArgs<string>, result: null } | 
        { key: "locations.subPathRescan", input: InstanceArgs<RescanArgs>, result: null } | 
        { key: "locations.update", input: InstanceArgs<LocationUpdateArgs>, result: null } | 
        { key: "nodes.edit", input: ChangeNodeNameArgs, result: null } | 
        { key: "notifications.test", input: never, result: null } | 
        { key: "notifications.testLibrary", input: InstanceArgs<null>, result: null } | 
        { key: "p2p.acceptSpacedrop", input: [string, string | null], result: null } | 
        { key: "p2p.cancelSpacedrop", input: string, result: null } | 
        { key: "p2p.pair", input: PeerId, result: number } | 
        { key: "p2p.pairingResponse", input: [number, PairingDecision], result: null } | 
        { key: "p2p.spacedrop", input: SpacedropArgs, result: null } | 
        { key: "preferences.update", input: InstanceArgs<LibraryPreferences>, result: null } | 
        { key: "tags.assign", input: InstanceArgs<TagAssignArgs>, result: null } | 
        { key: "tags.create", input: InstanceArgs<TagCreateArgs>, result: Tag } | 
        { key: "tags.delete", input: InstanceArgs<number>, result: null } | 
        { key: "tags.update", input: InstanceArgs<TagUpdateArgs>, result: null } | 
        { key: "toggleFeatureFlag", input: BackendFeature, result: null },
    subscriptions: 
        { key: "invalidation.listen", input: never, result: InvalidateOperationEvent[] } | 
        { key: "jobs.newThumbnail", input: InstanceArgs<null>, result: string[] } | 
        { key: "jobs.progress", input: InstanceArgs<null>, result: JobProgressEvent } | 
        { key: "locations.online", input: never, result: number[][] } | 
        { key: "locations.quickRescan", input: InstanceArgs<LightScanArgs>, result: null } | 
        { key: "notifications.listen", input: never, result: Notification } | 
        { key: "p2p.events", input: never, result: P2PEvent } | 
        { key: "sync.newMessage", input: InstanceArgs<null>, result: null }
};

export type AudioMetadata = { duration: number | null; audio_codec: string | null }

/**
 * All of the feature flags provided by the core itself. The frontend has it's own set of feature flags!
 * 
 * If you want a variant of this to show up on the frontend it must be added to `backendFeatures` in `useFeatureFlag.tsx`
 */
export type BackendFeature = "syncEmitMessages" | "filesOverP2P"

export type Backup = ({ id: string; timestamp: string; library_id: string; library_name: string }) & { path: string }

export type BuildInfo = { version: string; commit: string }

export type CRDTOperation = { instance: string; timestamp: number; id: string; typ: CRDTOperationType }

export type CRDTOperationType = SharedOperation | RelationOperation

/**
 * Meow
 */
export type Category = "Recents" | "Favorites" | "Albums" | "Photos" | "Videos" | "Movies" | "Music" | "Documents" | "Downloads" | "Encrypted" | "Projects" | "Applications" | "Archives" | "Databases" | "Games" | "Books" | "Contacts" | "Trash"

export type ChangeNodeNameArgs = { name: string | null }

export type ColorProfile = "Normal" | "Custom" | "HDRNoOriginal" | "HDRWithOriginal" | "OriginalForHDR" | "Panorama" | "PortraitHDR" | "Portrait"

export type Composite = "Unknown" | "False" | "General" | "Live"

export type CreateLibraryArgs = { name: LibraryName }

export type CursorOrderItem<T> = { order: SortOrder; data: T }

export type Dimensions = { width: number; height: number }

export type DiskType = "SSD" | "HDD" | "Removable"

export type DoubleClickAction = "openFile" | "quickPreview"

export type EditLibraryArgs = { id: string; name: LibraryName | null; description: MaybeUndefined<string> }

export type EphemeralPathOrder = { field: "name"; value: SortOrder } | { field: "sizeInBytes"; value: SortOrder } | { field: "dateCreated"; value: SortOrder } | { field: "dateModified"; value: SortOrder }

export type EphemeralPathSearchArgs = { path: string; withHiddenFiles: boolean; order?: EphemeralPathOrder | null }

export type Error = { code: ErrorCode; message: string }

/**
 * TODO
 */
export type ErrorCode = "BadRequest" | "Unauthorized" | "Forbidden" | "NotFound" | "Timeout" | "Conflict" | "PreconditionFailed" | "PayloadTooLarge" | "MethodNotSupported" | "ClientClosedRequest" | "InternalServerError"

export type ExplorerItem = { type: "Path"; has_local_thumbnail: boolean; thumbnail_key: string[] | null; item: FilePathWithObject } | { type: "Object"; has_local_thumbnail: boolean; thumbnail_key: string[] | null; item: ObjectWithFilePaths } | { type: "Location"; has_local_thumbnail: boolean; thumbnail_key: string[] | null; item: Location } | { type: "NonIndexedPath"; has_local_thumbnail: boolean; thumbnail_key: string[] | null; item: NonIndexedPathItem }

export type ExplorerLayout = "grid" | "list" | "media"

export type ExplorerSettings<TOrder> = { layoutMode: ExplorerLayout | null; gridItemSize: number | null; mediaColumns: number | null; mediaAspectSquare: boolean | null; openOnDoubleClick: DoubleClickAction | null; showBytesInGridView: boolean | null; colSizes: { [key: string]: number } | null; order?: TOrder | null }

export type FileCopierJobInit = { source_location_id: number; target_location_id: number; sources_file_path_ids: number[]; target_location_relative_directory_path: string; target_file_name_suffix: string | null }

export type FileCutterJobInit = { source_location_id: number; target_location_id: number; sources_file_path_ids: number[]; target_location_relative_directory_path: string }

export type FileDeleterJobInit = { location_id: number; file_path_ids: number[] }

export type FileEraserJobInit = { location_id: number; file_path_ids: number[]; passes: string }

export type FilePath = { id: number; pub_id: number[]; is_dir: boolean | null; cas_id: string | null; integrity_checksum: string | null; location_id: number | null; materialized_path: string | null; name: string | null; extension: string | null; size_in_bytes: string | null; size_in_bytes_bytes: number[] | null; inode: number[] | null; device: number[] | null; object_id: number | null; key_id: number | null; date_created: string | null; date_modified: string | null; date_indexed: string | null }

export type FilePathCursor = { isDir: boolean; variant: FilePathCursorVariant }

export type FilePathCursorVariant = "none" | { name: CursorOrderItem<string> } | { dateCreated: CursorOrderItem<string> } | { dateModified: CursorOrderItem<string> } | { dateIndexed: CursorOrderItem<string> } | { object: FilePathObjectCursor }

export type FilePathFilterArgs = { locationId?: number | null; search?: string | null; extension?: string | null; createdAt?: OptionalRange<string>; path?: string | null; object?: ObjectFilterArgs | null }

export type FilePathObjectCursor = { dateAccessed: CursorOrderItem<string> } | { kind: CursorOrderItem<number> }

export type FilePathOrder = { field: "name"; value: SortOrder } | { field: "sizeInBytes"; value: SortOrder } | { field: "dateCreated"; value: SortOrder } | { field: "dateModified"; value: SortOrder } | { field: "dateIndexed"; value: SortOrder } | { field: "object"; value: ObjectOrder }

export type FilePathSearchArgs = { take: number; orderAndPagination?: OrderAndPagination<number, FilePathOrder, FilePathCursor> | null; filter?: FilePathFilterArgs; groupDirectories?: boolean }

export type FilePathWithObject = { id: number; pub_id: number[]; is_dir: boolean | null; cas_id: string | null; integrity_checksum: string | null; location_id: number | null; materialized_path: string | null; name: string | null; extension: string | null; size_in_bytes: string | null; size_in_bytes_bytes: number[] | null; inode: number[] | null; device: number[] | null; object_id: number | null; key_id: number | null; date_created: string | null; date_modified: string | null; date_indexed: string | null; object: Object | null }

export type Flash = { mode: FlashMode; fired: boolean | null; returned: boolean | null; red_eye_reduction: boolean | null }

export type FlashMode = "Unknown" | "On" | "Off" | "Auto" | "Forced"

export type FromPattern = { pattern: string; replace_all: boolean }

export type FullRescanArgs = { location_id: number; reidentify_objects: boolean }

export type GenerateThumbsForLocationArgs = { id: number; path: string; regenerate?: boolean }

export type GetAll = { backups: Backup[]; directory: string }

export type GetArgs = { id: number }

export type Header = { id: string; timestamp: string; library_id: string; library_name: string }

export type IdentifyUniqueFilesArgs = { id: number; path: string }

export type ImageData = { device_make: string | null; device_model: string | null; color_space: string | null; color_profile: ColorProfile | null; focal_length: number | null; shutter_speed: number | null; flash: Flash | null; orientation: Orientation; lens_make: string | null; lens_model: string | null; bit_depth: number | null; red_eye: boolean | null; zoom: number | null; iso: number | null; software: string | null; serial_number: string | null; lens_serial_number: string | null; contrast: number | null; saturation: number | null; sharpness: number | null; composite: Composite | null }

export type ImageMetadata = { dimensions: Dimensions; date_taken: MediaTime; location: MediaLocation | null; camera_data: ImageData; artist: string | null; description: string | null; copyright: string | null; exif_version: string | null }

export type IndexerRule = { id: number; pub_id: number[]; name: string | null; default: boolean | null; rules_per_kind: number[] | null; date_created: string | null; date_modified: string | null }

/**
 * `IndexerRuleCreateArgs` is the argument received from the client using rspc to create a new indexer rule.
 * Note that `rules` field is a vector of tuples of `RuleKind` and `parameters`.
 * 
 * In case of  `RuleKind::AcceptFilesByGlob` or `RuleKind::RejectFilesByGlob`, it will be a
 * vector of strings containing a glob patterns.
 * 
 * In case of `RuleKind::AcceptIfChildrenDirectoriesArePresent` or `RuleKind::RejectIfChildrenDirectoriesArePresent` the
 * `parameters` field must be a vector of strings containing the names of the directories.
 */
export type IndexerRuleCreateArgs = { name: string; dry_run: boolean; rules: ([RuleKind, string[]])[] }

/**
 * Can wrap a query argument to require it to contain a `instance_id` and provide helpers for working with libraries.
 */
export type InstanceArgs<T> = { instance_id: string; arg: T }

/**
 * LibraryConfig holds the configuration for a specific library. This is stored as a '{uuid}.sdlibrary' file.
 */
export type InstanceConfig = { name: LibraryName; description: string | null; instance_id: number }

export type InstanceState = "Unavailable" | { Discovered: PeerId } | { Connected: PeerId }

export type InvalidateOperationEvent = { type: "single"; data: SingleInvalidateOperationEvent } | { type: "all" }

export type JobGroup = { id: string; action: string | null; status: JobStatus; created_at: string; jobs: JobReport[] }

export type JobProgressEvent = { id: string; task_count: number; completed_task_count: number; message: string; estimated_completion: string }

export type JobReport = { id: string; name: string; action: string | null; data: number[] | null; metadata: any | null; is_background: boolean; errors_text: string[]; created_at: string | null; started_at: string | null; completed_at: string | null; parent_id: string | null; status: JobStatus; task_count: number; completed_task_count: number; message: string; estimated_completion: string }

export type JobStatus = "Queued" | "Running" | "Completed" | "Canceled" | "Failed" | "Paused" | "CompletedWithErrors"

export type LibraryConfigWrapped = { uuid: string; instance_id: string; instance_public_key: string; config: InstanceConfig }

export type LibraryData = { instances: { [key: string]: InstanceState } }

export type LibraryName = string

export type LibraryPreferences = { location?: { [key: string]: LocationSettings } }

export type LightScanArgs = { location_id: number; sub_path: string }

export type Location = { id: number; pub_id: number[]; name: string | null; path: string | null; total_capacity: number | null; available_capacity: number | null; is_archived: boolean | null; generate_preview_media: boolean | null; sync_preview_media: boolean | null; hidden: boolean | null; date_created: string | null; instance_id: number | null }

/**
 * `LocationCreateArgs` is the argument received from the client using `rspc` to create a new location.
 * It has the actual path and a vector of indexer rules ids, to create many-to-many relationships
 * between the location and indexer rules.
 */
export type LocationCreateArgs = { path: string; dry_run: boolean; indexer_rules_ids: number[] }

export type LocationSettings = { explorer: ExplorerSettings<FilePathOrder> }

/**
 * `LocationUpdateArgs` is the argument received from the client using `rspc` to update a location.
 * It contains the id of the location to be updated, possible a name to change the current location's name
 * and a vector of indexer rules ids to add or remove from the location.
 * 
 * It is important to note that only the indexer rule ids in this vector will be used from now on.
 * Old rules that aren't in this vector will be purged.
 */
export type LocationUpdateArgs = { id: number; name: string | null; generate_preview_media: boolean | null; sync_preview_media: boolean | null; hidden: boolean | null; indexer_rules_ids: number[]; path: string | null }

export type LocationWithIndexerRules = { id: number; pub_id: number[]; name: string | null; path: string | null; total_capacity: number | null; available_capacity: number | null; is_archived: boolean | null; generate_preview_media: boolean | null; sync_preview_media: boolean | null; hidden: boolean | null; date_created: string | null; instance_id: number | null; indexer_rules: { indexer_rule: IndexerRule }[] }

export type MaybeNot<T> = T | { not: T }

export type MaybeUndefined<T> = null | null | T

export type MediaLocation = { latitude: number; longitude: number; pluscode: PlusCode; altitude: number | null; direction: number | null }

export type MediaMetadata = ({ type: "Image" } & ImageMetadata) | ({ type: "Video" } & VideoMetadata) | ({ type: "Audio" } & AudioMetadata)

/**
 * This can be either naive with no TZ (`YYYY-MM-DD HH-MM-SS`) or UTC with a fixed offset (`rfc3339`).
 * 
 * This may also be `undefined`.
 */
export type MediaTime = { Naive: string } | { Utc: string } | "Undefined"

export type NodeState = ({ id: string; name: string; p2p_port: number | null; features: BackendFeature[]; p2p_email: string | null; p2p_img_url: string | null }) & { data_path: string }

export type NonIndexedFileSystemEntries = { entries: ExplorerItem[]; errors: Error[] }

export type NonIndexedPathItem = { path: string; name: string; extension: string; kind: number; is_dir: boolean; date_created: string; date_modified: string; size_in_bytes_bytes: number[] }

/**
 * Represents a single notification.
 */
export type Notification = ({ type: "library"; id: [string, number] } | { type: "node"; id: number }) & { data: NotificationData; read: boolean; expires: string | null }

/**
 * Represents the data of a single notification.
 * This data is used by the frontend to properly display the notification.
 */
export type NotificationData = { PairingRequest: { id: string; pairing_id: number } } | "Test"

export type NotificationId = { type: "library"; id: [string, number] } | { type: "node"; id: number }

export type Object = { id: number; pub_id: number[]; kind: number | null; key_id: number | null; hidden: boolean | null; favorite: boolean | null; important: boolean | null; note: string | null; date_created: string | null; date_accessed: string | null }

export type ObjectCursor = "none" | { dateAccessed: CursorOrderItem<string> } | { kind: CursorOrderItem<number> }

export type ObjectFilterArgs = { favorite?: boolean | null; hidden?: ObjectHiddenFilter; dateAccessed?: MaybeNot<string | null> | null; kind?: number[]; tags?: number[]; category?: Category | null }

export type ObjectHiddenFilter = "exclude" | "include"

export type ObjectOrder = { field: "dateAccessed"; value: SortOrder } | { field: "kind"; value: SortOrder }

export type ObjectSearchArgs = { take: number; orderAndPagination?: OrderAndPagination<number, ObjectOrder, ObjectCursor> | null; filter?: ObjectFilterArgs }

export type ObjectValidatorArgs = { id: number; path: string }

export type ObjectWithFilePaths = { id: number; pub_id: number[]; kind: number | null; key_id: number | null; hidden: boolean | null; favorite: boolean | null; important: boolean | null; note: string | null; date_created: string | null; date_accessed: string | null; file_paths: FilePath[] }

/**
 * Represents the operating system which the remote peer is running.
 * This is not used internally and predominantly is designed to be used for display purposes by the embedding application.
 */
export type OperatingSystem = "Windows" | "Linux" | "MacOS" | "Ios" | "Android" | { Other: string }

export type OptionalRange<T> = { from: T | null; to: T | null }

export type OrderAndPagination<TId, TOrder, TCursor> = { orderOnly: TOrder } | { offset: { offset: number; order: TOrder | null } } | { cursor: { id: TId; cursor: TCursor } }

export type Orientation = "Normal" | "CW90" | "CW180" | "CW270" | "MirroredVertical" | "MirroredHorizontal" | "MirroredHorizontalAnd90CW" | "MirroredHorizontalAnd270CW"

/**
 * TODO: P2P event for the frontend
 */
export type P2PEvent = { type: "DiscoveredPeer"; peer_id: PeerId; metadata: PeerMetadata } | { type: "ExpiredPeer"; peer_id: PeerId } | { type: "ConnectedPeer"; peer_id: PeerId } | { type: "DisconnectedPeer"; peer_id: PeerId } | { type: "SpacedropRequest"; id: string; peer_id: PeerId; peer_name: string; file_name: string } | { type: "SpacedropProgress"; id: string; percent: number } | { type: "SpacedropRejected"; id: string } | { type: "PairingRequest"; id: number; name: string; os: OperatingSystem } | { type: "PairingProgress"; id: number; status: PairingStatus }

export type PairingDecision = { decision: "accept"; libraryId: string } | { decision: "reject" }

export type PairingStatus = { type: "EstablishingConnection" } | { type: "PairingRequested" } | { type: "LibraryAlreadyExists" } | { type: "PairingDecisionRequest" } | { type: "PairingInProgress"; data: { library_name: string; library_description: string | null } } | { type: "InitialSyncProgress"; data: number } | { type: "PairingComplete"; data: string } | { type: "PairingRejected" }

export type PeerId = string

export type PeerMetadata = { name: string; operating_system: OperatingSystem | null; version: string | null; email: string | null; img_url: string | null }

export type PlusCode = string

export type RelationOperation = { relation_item: any; relation_group: any; relation: string; data: RelationOperationData }

export type RelationOperationData = "c" | { u: { field: string; value: any } } | "d"

export type RenameFileArgs = { location_id: number; kind: RenameKind }

export type RenameKind = { One: RenameOne } | { Many: RenameMany }

export type RenameMany = { from_pattern: FromPattern; to_pattern: string; from_file_path_ids: number[] }

export type RenameOne = { from_file_path_id: number; to: string }

export type RescanArgs = { location_id: number; sub_path: string }

export type RuleKind = "AcceptFilesByGlob" | "RejectFilesByGlob" | "AcceptIfChildrenDirectoriesArePresent" | "RejectIfChildrenDirectoriesArePresent"

export type SanitisedNodeConfig = { id: string; name: string; p2p_port: number | null; features: BackendFeature[]; p2p_email: string | null; p2p_img_url: string | null }

export type SearchData<T> = { cursor: number[] | null; items: T[] }

export type SetFavoriteArgs = { id: number; favorite: boolean }

export type SetNoteArgs = { id: number; note: string | null }

export type SharedOperation = { record_id: any; model: string; data: SharedOperationData }

export type SharedOperationData = "c" | { u: { field: string; value: any } } | "d"

export type SingleInvalidateOperationEvent = { key: string; arg: any; result: any | null }

export type SortOrder = "Asc" | "Desc"

export type SpacedropArgs = { peer_id: PeerId; file_path: string[] }

export type Statistics = { id: number; date_captured: string; total_object_count: number; library_db_size: string; total_bytes_used: string; total_bytes_capacity: string; total_unique_bytes: string; total_bytes_free: string; preview_media_bytes: string }

export type Tag = { id: number; pub_id: number[]; name: string | null; color: string | null; redundancy_goal: number | null; date_created: string | null; date_modified: string | null }

export type TagAssignArgs = { object_ids: number[]; tag_id: number; unassign: boolean }

export type TagCreateArgs = { name: string; color: string }

export type TagUpdateArgs = { id: number; name: string | null; color: string | null }

export type VideoMetadata = { duration: number | null; video_codec: string | null; audio_codec: string | null }

export type Volume = { name: string; mount_points: string[]; total_capacity: string; available_capacity: string; disk_type: DiskType; file_system: string | null; is_root_filesystem: boolean }

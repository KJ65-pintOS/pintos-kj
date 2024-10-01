/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */
// anonymous page를 위한 기능을 제공합니다 (vm_type = VM_ANON).

#include "vm/vm.h"
#include "devices/disk.h"
#include <bitmap.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);
static void anon_pg_read(struct anon_page *anon_page, void *kva);
static disk_sector_t anon_pg_write(struct frame *frame);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Implementations */
static struct disk *swap_disk;
static struct bitmap *free_map; /* Free map, one bit per disk sector. bitmap for anon->disk_sector */
static struct lock swap_lock; 
static int PG_SEGMENTS_IN_DISK = PGSIZE / DISK_SECTOR_SIZE;
static disk_sector_t DISK_SECTOR_INIT = -1;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);

	/* init the free map */
	size_t total_pages_in_disk = (disk_size(swap_disk) * DISK_SECTOR_SIZE) / PGSIZE;
	free_map = bitmap_create(total_pages_in_disk);
	lock_init(&swap_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->saved_disk_sector = DISK_SECTOR_INIT;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	anon_pg_read(anon_page, kva);
	anon_page->saved_disk_sector = DISK_SECTOR_INIT;
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	anon_page->saved_disk_sector = anon_pg_write(page->frame);
	page->frame = NULL;
	pml4_clear_page(page->plm4, page->va);
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	return;
}

static disk_sector_t anon_pg_write(struct frame *frame) {
	lock_acquire(&swap_lock);
	size_t bitmap_idx = bitmap_scan_and_flip(free_map, 0, 1, false);
	lock_release(&swap_lock);
	// 한 섹터의 크기 = DISK_SECTOR_SIZE 512. disk 하나의 idx당 넣을 수 있는 크기	
	disk_sector_t saved_disk_sector = (PG_SEGMENTS_IN_DISK) * bitmap_idx;

	void *kpage = frame->kva;
	for (int i = 0; i < PG_SEGMENTS_IN_DISK; i++) {
		disk_write(swap_disk, (saved_disk_sector + i), kpage + (DISK_SECTOR_SIZE * i));
	}

	return saved_disk_sector;
}

static void anon_pg_read(struct anon_page *anon_page, void *kva) { 
	disk_sector_t saved_disk_sector = anon_page->saved_disk_sector;

	for (int i = 0; i < PG_SEGMENTS_IN_DISK; i++) {
		disk_read(swap_disk, (saved_disk_sector + i), kva + (DISK_SECTOR_SIZE * i));
	}
	
	lock_acquire(&swap_lock);
	bitmap_set(free_map, saved_disk_sector / PG_SEGMENTS_IN_DISK, false);
	lock_release(&swap_lock);
}
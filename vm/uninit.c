/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"
/* project 3*/
#include <string.h>
#include "userprog/process.h"

static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);
static bool
uninit_duplicate(struct page* dst, const struct page* src);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.duplicate = uninit_duplicate,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void
uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *)) {
	ASSERT (page != NULL);

	*page = (struct page) {
		.operations = &uninit_ops,
		.va = va,
		/* modified*/
		.type = type,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page) {
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}
	};
}

/* Initalize the page on first fault */
static bool
uninit_initialize (struct page *page, void *kva) {
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* TODO: You may need to fix this function. */
	return uninit->page_initializer (page, uninit->type, kva) &&
		(init ? init (page, aux) : true);
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void
uninit_destroy (struct page *page) {
	struct uninit_page *uninit UNUSED = &page->uninit;
	void* aux;
	/* TODO: Fill this function.
	 * TODO: If you don't have anything to do, just return. */
	
	aux = uninit->aux;
	if(aux)
		free(aux);
}

static bool
uninit_duplicate(struct page* dst, const struct page* src){
	struct uninit_page *uninit;
	struct load_args* aux;

	ASSERT( dst != NULL && src != NULL);

	uninit = NULL;
	aux = NULL;

	memcpy(dst, src, sizeof(struct page));
	uninit = &dst->uninit;
	if((aux = malloc(sizeof(struct load_args))) == NULL)
		goto err;
	memcpy(aux, uninit->aux, sizeof(struct load_args));
	uninit->aux = aux;
	return true;
err:
	if(aux)
		free(aux);
	return false;
}